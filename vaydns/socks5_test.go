package vaydns

import (
	"io"
	"net"
	"testing"

	"github.com/xtaci/smux"
)

// loopbackTCPPair returns a connected *net.TCPConn pair over loopback.
// handleWithAuth requires *net.TCPConn, so net.Pipe() isn't sufficient.
func loopbackTCPPair(t *testing.T) (client, server *net.TCPConn) {
	t.Helper()
	ln, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	accepted := make(chan *net.TCPConn, 1)
	go func() {
		c, err := ln.AcceptTCP()
		if err != nil {
			accepted <- nil
			return
		}
		accepted <- c
	}()

	c, err := net.DialTCP("tcp", nil, ln.Addr().(*net.TCPAddr))
	if err != nil {
		t.Fatal(err)
	}
	s := <-accepted
	if s == nil {
		t.Fatal("accept failed")
	}
	return c, s
}

// smuxPair returns a connected client/server smux.Session pair over net.Pipe.
func smuxPair(t *testing.T) (client, server *smux.Session) {
	t.Helper()
	c, s := net.Pipe()
	cl, err := smux.Client(c, nil)
	if err != nil {
		t.Fatal(err)
	}
	sv, err := smux.Server(s, nil)
	if err != nil {
		t.Fatal(err)
	}
	return cl, sv
}

// serveSocks5WithAuth simulates a SOCKS5 server that requires user/pass auth.
// It accepts one smux stream, performs the auth handshake, then replies with a
// CONNECT success response and closes.
func serveSocks5WithAuth(t *testing.T, sess *smux.Session, wantUser, wantPass string) {
	t.Helper()
	stream, err := sess.AcceptStream()
	if err != nil {
		t.Logf("server AcceptStream: %v", err)
		return
	}
	defer stream.Close()

	// Read greeting from handleWithAuth: {5, 2, 0x00, 0x02}
	greeting := make([]byte, 4)
	if _, err := io.ReadFull(stream, greeting); err != nil {
		t.Logf("server read greeting: %v", err)
		return
	}

	// Pick user/pass (0x02)
	stream.Write([]byte{5, 0x02})

	// Read auth: [ver, ulen, uname..., plen, passwd...]
	authHdr := make([]byte, 2)
	if _, err := io.ReadFull(stream, authHdr); err != nil {
		return
	}
	uname := make([]byte, authHdr[1])
	io.ReadFull(stream, uname)
	plenBuf := make([]byte, 1)
	io.ReadFull(stream, plenBuf)
	passwd := make([]byte, plenBuf[0])
	io.ReadFull(stream, passwd)

	if string(uname) != wantUser || string(passwd) != wantPass {
		stream.Write([]byte{1, 1}) // auth failure
		t.Errorf("server got credentials %q:%q, want %q:%q", uname, passwd, wantUser, wantPass)
		return
	}
	stream.Write([]byte{1, 0}) // auth success

	// Read CONNECT (IPv4, 10 bytes: {5,1,0,1,127,0,0,1,0,80})
	req := make([]byte, 10)
	io.ReadFull(stream, req)

	// Reply: CONNECT success, bound to 127.0.0.1:80
	stream.Write([]byte{5, 0, 0, 1, 127, 0, 0, 1, 0, 80})
}

// TestHandleWithAuth_InjectsCredentials verifies the core behavior of the
// credential-injection path:
//
//   - The user-facing client connects with no-auth.
//   - handleWithAuth injects the stored credentials toward the server.
//   - The client receives {5, 0} (no authentication required).
//   - The CONNECT request is forwarded and the server reply reaches the client.
func TestHandleWithAuth_InjectsCredentials(t *testing.T) {
	smuxClient, smuxServer := smuxPair(t)
	defer smuxClient.Close()
	defer smuxServer.Close()

	userFacing, localConn := loopbackTCPPair(t)
	defer userFacing.Close()
	defer localConn.Close()

	// Simulate the upstream SOCKS5 server in a goroutine.
	serverDone := make(chan struct{})
	go func() {
		defer close(serverDone)
		serveSocks5WithAuth(t, smuxServer, "user", "pass")
	}()

	// Run handleWithAuth in a goroutine.
	errCh := make(chan error, 1)
	go func() {
		errCh <- handleWithAuth(localConn, smuxClient, 0xdead, "user", "pass")
	}()

	// Client: send SOCKS5 greeting with no-auth method only.
	userFacing.Write([]byte{0x05, 0x01, 0x00})

	resp := make([]byte, 2)
	if _, err := io.ReadFull(userFacing, resp); err != nil {
		t.Fatalf("reading method selection: %v", err)
	}
	if resp[0] != 5 || resp[1] != 0 {
		t.Fatalf("client expected no-auth {5,0}, got {%d,%d}", resp[0], resp[1])
	}

	// Client: send CONNECT to 127.0.0.1:80
	userFacing.Write([]byte{5, 1, 0, 1, 127, 0, 0, 1, 0, 80})

	// Expect CONNECT success response forwarded from the server.
	connectResp := make([]byte, 10)
	if _, err := io.ReadFull(userFacing, connectResp); err != nil {
		t.Fatalf("reading CONNECT response: %v", err)
	}
	if connectResp[1] != 0 {
		t.Errorf("CONNECT reply field: want 0 (success), got %d", connectResp[1])
	}

	// Close the user-facing side to unblock the relay goroutines.
	userFacing.Close()
	<-serverDone

	if err := <-errCh; err != nil {
		t.Errorf("handleWithAuth returned error: %v", err)
	}
}

// TestHandleWithAuth_ServerNoAuth verifies that when the server requires no
// auth, the credential injection is skipped and the handshake still succeeds.
func TestHandleWithAuth_ServerNoAuth(t *testing.T) {
	smuxClient, smuxServer := smuxPair(t)
	defer smuxClient.Close()
	defer smuxServer.Close()

	userFacing, localConn := loopbackTCPPair(t)
	defer userFacing.Close()
	defer localConn.Close()

	go func() {
		stream, err := smuxServer.AcceptStream()
		if err != nil {
			return
		}
		defer stream.Close()
		greeting := make([]byte, 4)
		io.ReadFull(stream, greeting)
		stream.Write([]byte{5, 0x00}) // no auth required
		req := make([]byte, 10)
		io.ReadFull(stream, req)
		stream.Write([]byte{5, 0, 0, 1, 127, 0, 0, 1, 0, 80})
	}()

	errCh := make(chan error, 1)
	go func() {
		errCh <- handleWithAuth(localConn, smuxClient, 0, "user", "pass")
	}()

	userFacing.Write([]byte{0x05, 0x01, 0x00})
	resp := make([]byte, 2)
	io.ReadFull(userFacing, resp)
	if resp[1] != 0 {
		t.Fatalf("expected no-auth {5,0}, got {%d,%d}", resp[0], resp[1])
	}

	userFacing.Write([]byte{5, 1, 0, 1, 127, 0, 0, 1, 0, 80})
	connectResp := make([]byte, 10)
	if _, err := io.ReadFull(userFacing, connectResp); err != nil {
		t.Fatalf("CONNECT response: %v", err)
	}
	if connectResp[1] != 0 {
		t.Errorf("expected CONNECT success, got rep=%d", connectResp[1])
	}

	userFacing.Close()
	if err := <-errCh; err != nil {
		t.Errorf("handleWithAuth: %v", err)
	}
}
