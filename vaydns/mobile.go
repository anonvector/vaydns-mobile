// Package mobile provides a gomobile-compatible API for the VayDNS client.
//
// It supports four DNS transport modes, auto-detected from the dnsAddr
// parameter passed to NewClient:
//
//   - "https://..." → DoH (DNS over HTTPS) with HTTP/2 and uTLS fingerprinting
//   - "tls://host:port" → DoT (DNS over TLS) with uTLS fingerprinting
//   - "tcp://host:port" → DNS over TCP (plain TCP, no encryption)
//   - "host:port" → plain UDP DNS
//
// Multiple resolvers can be comma-separated (e.g., "8.8.8.8:53,1.1.1.1:53").
// Queries fan out to all alive resolvers; KCP deduplicates responses.
package vaydns

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	vayclient "github.com/net2share/vaydns/client"
	"github.com/net2share/vaydns/dns"
	"github.com/net2share/vaydns/noise"
	"github.com/net2share/vaydns/turbotunnel"
	utls "github.com/refraction-networking/utls"
	"github.com/xtaci/kcp-go/v5"
	"github.com/xtaci/smux"
	"golang.org/x/net/http2"
)

// Default uTLS fingerprint distribution.
const defaultUTLSDistribution = "4*random,3*Firefox_120,1*Firefox_105,3*Chrome_120,1*Chrome_102,1*iOS_14,1*iOS_13"

// VaydnsClient wraps a VayDNS tunnel client with Start/Stop lifecycle.
type VaydnsClient struct {
	dnsAddr      string
	tunnelDomain string
	pubkey       []byte
	listenAddr   string

	// dnsttCompat enables the original dnstt wire format (8-byte ClientID,
	// padding prefixes) for compatibility with dnstt servers.
	dnsttCompat bool

	// clientIDSize overrides the ClientID size in bytes (default: 2).
	// Ignored when dnsttCompat is true.
	clientIDSize int

	// maxQnameLen overrides the maximum QNAME wire length.
	// 0 = 101 (VayDNS default) or 253 (with dnsttCompat).
	maxQnameLen int

	// maxPayload caps the KCP MTU (bytes per DNS query payload).
	// 0 = use full capacity (default).
	maxPayload int

	// recordType selects the DNS record type for downstream data.
	// Supported: "txt" (default), "cname", "a", "aaaa", "mx", "ns", "srv", "null", "caa".
	recordType string

	// rpsLimit limits outgoing DNS queries per second (token bucket).
	// 0 = unlimited (default).
	rpsLimit float64

	// maxNumLabels is the maximum number of data labels in the query name.
	// 0 = unlimited (default).
	maxNumLabels int

	// idleTimeout overrides the smux KeepAliveTimeout (session idle timeout).
	// 0 = use default (10s for VayDNS, 2min for dnstt compat).
	idleTimeout time.Duration

	// keepAlive overrides the smux KeepAliveInterval.
	// 0 = use default (2s for VayDNS, 10s for dnstt compat).
	keepAlive time.Duration

	// udpTimeout overrides the per-query UDP response timeout.
	// 0 = use default (internal default, typically 500ms).
	udpTimeout time.Duration

	// utlsDistribution overrides the default uTLS fingerprint distribution.
	// Empty = use default. "none" = disable uTLS.
	utlsDistribution string

	// socksUser/socksPass are injected automatically during the SOCKS5
	// handshake so that local clients never need to supply credentials.
	socksUser string
	socksPass string

	// resolverMode controls multi-resolver query distribution.
	// "fanout" (default) sends to all alive resolvers.
	// "roundrobin" sends to one resolver at a time for bandwidth aggregation.
	resolverMode ResolverMode

	// rrSpreadCount controls how many resolvers each query is sent to in
	// round-robin mode. Default 3 (1 primary + 2 redundant). Minimum 1.
	rrSpreadCount int

	mu            sync.Mutex
	running       bool
	cancel        context.CancelFunc
	listener      net.Listener
	transportConn net.PacketConn
	kcpConn       net.Conn
}

// NewClient creates a new VayDNS client. Transport is auto-detected from dnsAddr:
//
//   - "https://..." → DoH (HTTP/2 + uTLS fingerprint)
//   - "tls://host:port" → DoT (TLS + uTLS fingerprint)
//   - "tcp://host:port" → DNS over TCP (plain, no encryption)
//   - "host:port" → UDP
func NewClient(dnsAddr, tunnelDomain, publicKey, listenAddr string) (*VaydnsClient, error) {
	if tunnelDomain == "" {
		return nil, fmt.Errorf("tunnel domain is required")
	}
	if publicKey == "" {
		return nil, fmt.Errorf("public key is required")
	}
	if listenAddr == "" {
		return nil, fmt.Errorf("listen address is required")
	}

	pubkey, err := noise.DecodeKey(publicKey)
	if err != nil {
		return nil, fmt.Errorf("invalid public key: %v", err)
	}

	return &VaydnsClient{
		dnsAddr:      dnsAddr,
		tunnelDomain: tunnelDomain,
		pubkey:       pubkey,
		listenAddr:   listenAddr,
	}, nil
}

// SetDnsttCompat enables or disables the original dnstt wire format.
// When true, uses 8-byte ClientID with padding prefixes for compatibility
// with dnstt servers. Must be called before Start.
func (c *VaydnsClient) SetDnsttCompat(enabled bool) {
	c.dnsttCompat = enabled
}

// SetClientIDSize overrides the ClientID size in bytes (default: 2).
// Ignored when DnsttCompat is true. Must be called before Start.
func (c *VaydnsClient) SetClientIDSize(size int) {
	c.clientIDSize = size
}

// SetMaxQnameLen overrides the maximum QNAME wire length.
// 0 = use default (101 for VayDNS, 253 for dnstt compat).
// Must be called before Start.
func (c *VaydnsClient) SetMaxQnameLen(length int) {
	c.maxQnameLen = length
}

// SetMaxPayload caps the per-query payload size (KCP MTU).
// 0 = use full capacity (default). Must be called before Start.
func (c *VaydnsClient) SetMaxPayload(size int) {
	c.maxPayload = size
}

// SetRecordType sets the DNS record type for downstream data.
// Supported: "txt" (default), "cname", "a", "aaaa", "mx", "ns", "srv", "null", "caa".
// Must be called before Start.
func (c *VaydnsClient) SetRecordType(recordType string) {
	c.recordType = recordType
}

// SetUTLSFingerprint overrides the uTLS fingerprint selection.
// "none" disables uTLS. Empty string uses the default distribution.
// Must be called before Start.
func (c *VaydnsClient) SetUTLSFingerprint(fingerprint string) {
	c.utlsDistribution = fingerprint
}

// SetRPS limits outgoing DNS queries per second.
// 0 = unlimited (default). Must be called before Start.
func (c *VaydnsClient) SetRPS(rps float64) {
	c.rpsLimit = rps
}

// SetMaxNumLabels sets the maximum number of data labels in the query name.
// 0 = unlimited (default). Must be called before Start.
func (c *VaydnsClient) SetMaxNumLabels(n int) {
	c.maxNumLabels = n
}

// SetIdleTimeout overrides the smux KeepAliveTimeout (session idle timeout).
// Value is in seconds. 0 = use default. Must be called before Start.
func (c *VaydnsClient) SetIdleTimeout(seconds int) {
	if seconds > 0 {
		c.idleTimeout = time.Duration(seconds) * time.Second
	}
}

// SetKeepAlive overrides the smux KeepAliveInterval.
// Value is in seconds. 0 = use default. Must be called before Start.
func (c *VaydnsClient) SetKeepAlive(seconds int) {
	if seconds > 0 {
		c.keepAlive = time.Duration(seconds) * time.Second
	}
}

// SetSocksCredentials sets the SOCKS5 username and password to inject
// automatically during the SOCKS5 handshake with the server.
// Must be called before Start.
func (c *VaydnsClient) SetSocksCredentials(user, pass string) {
	c.socksUser = user
	c.socksPass = pass
}

// SetResolverMode sets the multi-resolver query distribution mode.
// "fanout" (default) sends to all alive resolvers for reliability.
// "roundrobin" sends to one resolver at a time for bandwidth aggregation.
// Must be called before Start.
func (c *VaydnsClient) SetResolverMode(mode string) {
	switch ResolverMode(mode) {
	case ModeRoundRobin:
		c.resolverMode = ModeRoundRobin
	default:
		c.resolverMode = ModeFanout
	}
}

// SetRRSpreadCount sets how many resolvers each query is sent to in
// round-robin mode (1 primary + N-1 redundant). Default 3. Minimum 1.
// Has no effect in fanout mode. Must be called before Start.
func (c *VaydnsClient) SetRRSpreadCount(n int64) {
	if n < 1 {
		n = 3
	}
	c.rrSpreadCount = int(n)
}

// SetUDPTimeout overrides the per-query UDP response timeout.
// Value is in milliseconds. 0 = use default. Must be called before Start.
func (c *VaydnsClient) SetUDPTimeout(ms int) {
	if ms > 0 {
		c.udpTimeout = time.Duration(ms) * time.Millisecond
	}
}

// Start begins the VayDNS tunnel in a background goroutine.
func (c *VaydnsClient) Start() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.running {
		return fmt.Errorf("client is already running")
	}

	ctx, cancel := context.WithCancel(context.Background())
	c.cancel = cancel

	domain, err := dns.ParseName(c.tunnelDomain)
	if err != nil {
		cancel()
		return fmt.Errorf("invalid tunnel domain: %v", err)
	}

	// Build wire config.
	wireConfig := c.buildWireConfig()

	// Determine RR type.
	var rrType uint16
	if c.recordType != "" {
		rrType, err = dns.ParseRecordType(c.recordType)
		if err != nil {
			cancel()
			return fmt.Errorf("invalid record type %q: %v", c.recordType, err)
		}
	} else {
		rrType = dns.RRTypeTXT
	}

	// Sample uTLS fingerprint.
	utlsDist := defaultUTLSDistribution
	if c.utlsDistribution != "" {
		utlsDist = c.utlsDistribution
	}
	var utlsID *utls.ClientHelloID
	if utlsDist != "none" {
		utlsID, err = vayclient.SampleUTLSDistribution(utlsDist)
		if err != nil {
			cancel()
			return fmt.Errorf("sampling uTLS distribution: %v", err)
		}
		if utlsID != nil {
			log.Printf("uTLS fingerprint %s %s", utlsID.Client, utlsID.Version)
		}
	}

	// Create transport based on address prefix.
	var remoteAddr net.Addr
	var pconn net.PacketConn

	switch {
	case strings.HasPrefix(c.dnsAddr, "https://"):
		pconn, remoteAddr, err = c.createDoHTransport(utlsID)
	case strings.Contains(c.dnsAddr, "tls://"):
		pconn, remoteAddr, err = c.createDoTTransport(utlsID)
	case strings.Contains(c.dnsAddr, "tcp://"):
		pconn, remoteAddr, err = c.createTCPTransport()
	default:
		pconn, remoteAddr, err = c.createUDPTransport()
	}
	if err != nil {
		cancel()
		return err
	}

	transportConn := pconn
	c.transportConn = pconn

	// Wrap with DNSPacketConn for DNS encoding.
	maxQnameLen := c.effectiveMaxQnameLen()
	var rateLimiter *vayclient.RateLimiter
	if c.rpsLimit > 0 {
		rateLimiter = vayclient.NewRateLimiter(c.rpsLimit)
	}
	pconn = vayclient.NewDNSPacketConn(pconn, remoteAddr, domain, rateLimiter, maxQnameLen, c.maxNumLabels, wireConfig, nil, rrType, turbotunnel.QueueSize, turbotunnel.QueueOverflowDrop)

	if remoteAddr == (turbotunnel.DummyAddr{}) {
		pconn = &AddrNormConn{PacketConn: pconn, fixedAddr: turbotunnel.DummyAddr{}}
	}

	localAddr, err := net.ResolveTCPAddr("tcp", c.listenAddr)
	if err != nil {
		pconn.Close()
		cancel()
		return fmt.Errorf("resolving listen address: %v", err)
	}

	c.running = true

	go func() {
		defer transportConn.Close()
		err := c.run(ctx, domain, localAddr, remoteAddr, pconn, wireConfig)
		if err != nil && ctx.Err() == nil {
			log.Printf("vaydns client: %v", err)
		}
		c.mu.Lock()
		c.running = false
		c.mu.Unlock()
	}()

	return nil
}

// Stop shuts down the VayDNS tunnel.
func (c *VaydnsClient) Stop() {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.cancel != nil {
		c.cancel()
		c.cancel = nil
	}
	if c.kcpConn != nil {
		c.kcpConn.SetDeadline(time.Now())
	}
	if c.listener != nil {
		c.listener.Close()
		c.listener = nil
	}
	if c.transportConn != nil {
		c.transportConn.Close()
		c.transportConn = nil
	}
	c.running = false
}

// IsRunning returns whether the client is currently running.
func (c *VaydnsClient) IsRunning() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.running
}

// buildWireConfig constructs the wire protocol configuration.
func (c *VaydnsClient) buildWireConfig() turbotunnel.WireConfig {
	if c.dnsttCompat {
		return turbotunnel.WireConfig{ClientIDSize: 8, Compat: true}
	}
	size := c.clientIDSize
	if size <= 0 {
		size = 2
	}
	return turbotunnel.WireConfig{ClientIDSize: size}
}

// effectiveMaxQnameLen returns the max QNAME length.
func (c *VaydnsClient) effectiveMaxQnameLen() int {
	if c.maxQnameLen > 0 {
		return c.maxQnameLen
	}
	if c.dnsttCompat {
		return 253
	}
	return 101
}

// createDoHTransport creates a DoH (HTTPS) transport.
func (c *VaydnsClient) createDoHTransport(utlsID *utls.ClientHelloID) (net.PacketConn, net.Addr, error) {
	var rt http.RoundTripper
	if utlsID == nil {
		rt = http.DefaultTransport.(*http.Transport).Clone()
	} else {
		rt = vayclient.NewUTLSRoundTripper(nil, utlsID)
	}
	pconn, err := vayclient.NewHTTPPacketConn(rt, c.dnsAddr, 8, turbotunnel.QueueSize, turbotunnel.QueueOverflowDrop)
	if err != nil {
		return nil, nil, fmt.Errorf("creating DoH transport: %v", err)
	}
	return pconn, turbotunnel.DummyAddr{}, nil
}

// createDoTTransport creates a DoT (TLS) transport, with multi-resolver support.
func (c *VaydnsClient) createDoTTransport(utlsID *utls.ClientHelloID) (net.PacketConn, net.Addr, error) {
	var dialTLSContext func(ctx context.Context, network, addr string) (net.Conn, error)
	if utlsID == nil {
		dialTLSContext = (&tls.Dialer{}).DialContext
	} else {
		id := utlsID
		dialTLSContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
			return vayclient.UTLSDialContext(ctx, network, addr, nil, id)
		}
	}

	addrs := strings.Split(c.dnsAddr, ",")
	if len(addrs) == 1 {
		dotAddr := strings.TrimPrefix(strings.TrimSpace(addrs[0]), "tls://")
		pconn, err := vayclient.NewTLSPacketConn(dotAddr, dialTLSContext, turbotunnel.QueueSize, turbotunnel.QueueOverflowDrop)
		if err != nil {
			return nil, nil, fmt.Errorf("creating DoT transport: %v", err)
		}
		return pconn, turbotunnel.DummyAddr{}, nil
	}

	// Multi-resolver DoT.
	var transports []net.PacketConn
	var tAddrs []net.Addr
	for _, a := range addrs {
		dotAddr := strings.TrimPrefix(strings.TrimSpace(a), "tls://")
		t, err := vayclient.NewTLSPacketConn(dotAddr, dialTLSContext, turbotunnel.QueueSize, turbotunnel.QueueOverflowDrop)
		if err != nil {
			for _, prev := range transports {
				prev.Close()
			}
			return nil, nil, fmt.Errorf("creating DoT transport for %s: %v", dotAddr, err)
		}
		transports = append(transports, t)
		tAddrs = append(tAddrs, turbotunnel.DummyAddr{})
	}
	pconn := NewSmartMultiPacketConn(transports, tAddrs, c.resolverMode, c.rrSpreadCount)
	log.Printf("multi-resolver DoT: %d transports (mode=%s, spread=%d)", len(transports), c.resolverMode, c.rrSpreadCount)
	return pconn, turbotunnel.DummyAddr{}, nil
}

// createTCPTransport creates a plain TCP transport (DNS over TCP, no encryption),
// with multi-resolver support. Reuses TLSPacketConn's 2-byte length-prefixed
// framing and auto-reconnect logic with a plain TCP dialer.
func (c *VaydnsClient) createTCPTransport() (net.PacketConn, net.Addr, error) {
	dialTCPContext := func(ctx context.Context, network, addr string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, "tcp", addr)
	}

	addrs := strings.Split(c.dnsAddr, ",")
	if len(addrs) == 1 {
		tcpAddr := strings.TrimPrefix(strings.TrimSpace(addrs[0]), "tcp://")
		pconn, err := vayclient.NewTLSPacketConn(tcpAddr, dialTCPContext, turbotunnel.QueueSize, turbotunnel.QueueOverflowDrop)
		if err != nil {
			return nil, nil, fmt.Errorf("creating TCP transport: %v", err)
		}
		return pconn, turbotunnel.DummyAddr{}, nil
	}

	// Multi-resolver TCP.
	var transports []net.PacketConn
	var tAddrs []net.Addr
	for _, a := range addrs {
		tcpAddr := strings.TrimPrefix(strings.TrimSpace(a), "tcp://")
		t, err := vayclient.NewTLSPacketConn(tcpAddr, dialTCPContext, turbotunnel.QueueSize, turbotunnel.QueueOverflowDrop)
		if err != nil {
			for _, prev := range transports {
				prev.Close()
			}
			return nil, nil, fmt.Errorf("creating TCP transport for %s: %v", tcpAddr, err)
		}
		transports = append(transports, t)
		tAddrs = append(tAddrs, turbotunnel.DummyAddr{})
	}
	pconn := NewSmartMultiPacketConn(transports, tAddrs, c.resolverMode, c.rrSpreadCount)
	log.Printf("multi-resolver TCP: %d transports (mode=%s, spread=%d)", len(transports), c.resolverMode, c.rrSpreadCount)
	return pconn, turbotunnel.DummyAddr{}, nil
}

// createUDPTransport creates a plain UDP transport, with multi-resolver support.
func (c *VaydnsClient) createUDPTransport() (net.PacketConn, net.Addr, error) {
	addrs := strings.Split(c.dnsAddr, ",")
	if len(addrs) == 1 {
		remoteAddr, err := net.ResolveUDPAddr("udp", strings.TrimSpace(addrs[0]))
		if err != nil {
			return nil, nil, fmt.Errorf("resolving UDP address: %v", err)
		}
		pconn, err := net.ListenUDP("udp", nil)
		if err != nil {
			return nil, nil, fmt.Errorf("opening UDP socket: %v", err)
		}
		return pconn, remoteAddr, nil
	}

	// Multi-resolver UDP.
	var udpAddrs []*net.UDPAddr
	for _, a := range addrs {
		addr, err := net.ResolveUDPAddr("udp", strings.TrimSpace(a))
		if err != nil {
			return nil, nil, fmt.Errorf("resolving UDP address %s: %v", a, err)
		}
		udpAddrs = append(udpAddrs, addr)
	}
	sconn, err := NewSmartUDPConn(udpAddrs, c.resolverMode, c.rrSpreadCount)
	if err != nil {
		return nil, nil, fmt.Errorf("opening UDP socket: %v", err)
	}
	log.Printf("multi-resolver UDP: %d resolvers (mode=%s)", len(udpAddrs), c.resolverMode)
	return sconn, turbotunnel.DummyAddr{}, nil
}

// run is the main tunnel loop: KCP → Noise → smux → TCP listener.
func (c *VaydnsClient) run(ctx context.Context, domain dns.Name, localAddr *net.TCPAddr, remoteAddr net.Addr, pconn net.PacketConn, wireConfig turbotunnel.WireConfig) error {
	defer pconn.Close()

	ln, err := net.ListenTCP("tcp", localAddr)
	if err != nil {
		return fmt.Errorf("opening local listener: %v", err)
	}
	c.mu.Lock()
	c.listener = ln
	c.mu.Unlock()
	defer ln.Close()

	go func() {
		<-ctx.Done()
		ln.Close()
	}()

	// Compute MTU.
	maxQnameLen := c.effectiveMaxQnameLen()
	mtu := vayclient.DNSNameCapacity(domain, maxQnameLen, c.maxNumLabels) - wireConfig.DataOverhead()
	if mtu < 25 {
		return fmt.Errorf("domain %s leaves only %d bytes for payload; try a shorter tunnel domain", domain, mtu)
	}
	if c.maxPayload >= 25 && c.maxPayload < mtu {
		log.Printf("capping MTU from %d to %d (maxPayload)", mtu, c.maxPayload)
		mtu = c.maxPayload
	}
	log.Printf("max QNAME length %d, effective MTU %d bytes/query", maxQnameLen, mtu)

	conn, err := kcp.NewConn2(remoteAddr, nil, 0, 0, pconn)
	if err != nil {
		return fmt.Errorf("opening KCP conn: %v", err)
	}
	c.mu.Lock()
	c.kcpConn = conn
	c.mu.Unlock()
	defer func() {
		log.Printf("end session %08x", conn.GetConv())
		conn.Close()
		c.mu.Lock()
		c.kcpConn = nil
		c.mu.Unlock()
	}()
	log.Printf("begin session %08x", conn.GetConv())

	conn.SetStreamMode(true)
	conn.SetNoDelay(0, 0, 0, 1)
	conn.SetWindowSize(256, 256)
	if rc := conn.SetMtu(mtu); !rc {
		return fmt.Errorf("failed to set KCP MTU to %d", mtu)
	}

	// Noise handshake.
	rw, err := noise.NewClient(conn, c.pubkey)
	if err != nil {
		return err
	}

	// smux session.
	idleTimeout := 10 * time.Second
	keepAlive := 2 * time.Second
	if c.dnsttCompat {
		idleTimeout = 2 * time.Minute
		keepAlive = 10 * time.Second
	}
	if c.idleTimeout > 0 {
		idleTimeout = c.idleTimeout
	}
	if c.keepAlive > 0 {
		keepAlive = c.keepAlive
	}
	smuxConfig := smux.DefaultConfig()
	smuxConfig.Version = 2
	smuxConfig.KeepAliveInterval = keepAlive
	smuxConfig.KeepAliveTimeout = idleTimeout
	smuxConfig.MaxStreamBuffer = 1 * 1024 * 1024
	sess, err := smux.Client(rw, smuxConfig)
	if err != nil {
		return fmt.Errorf("opening smux session: %v", err)
	}
	defer sess.Close()

	streamSem := make(chan struct{}, 32)
	sessDone := sess.CloseChan()

	for {
		ln.SetDeadline(time.Now().Add(2 * time.Second))
		local, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				select {
				case <-sessDone:
					return fmt.Errorf("session %08x closed", conn.GetConv())
				default:
					continue
				}
			}
			if ne, ok := err.(net.Error); ok && ne.Temporary() {
				continue
			}
			return err
		}
		select {
		case <-sessDone:
			local.Close()
			return fmt.Errorf("session %08x closed", conn.GetConv())
		default:
		}
		select {
		case streamSem <- struct{}{}:
		default:
			local.Close()
			continue
		}
		go func() {
			defer local.Close()
			defer func() { <-streamSem }()
			err := handle(local.(*net.TCPConn), sess, conn.GetConv(), c.socksUser, c.socksPass)
			if err != nil && !sess.IsClosed() {
				log.Printf("handle: %v", err)
			}
		}()
	}
}

// handle proxies data between a local TCP connection and a smux stream.
// When socksUser is set, it intercepts the SOCKS5 handshake and injects
// credentials automatically so clients never need to supply them.
func handle(local *net.TCPConn, sess *smux.Session, conv uint32, socksUser, socksPass string) error {
	if socksUser != "" {
		return handleWithAuth(local, sess, conv, socksUser, socksPass)
	}

	stream, err := sess.OpenStream()
	if err != nil {
		return fmt.Errorf("session %08x opening stream: %v", conv, err)
	}
	defer func() {
		log.Printf("end stream %08x:%d", conv, stream.ID())
		stream.Close()
	}()
	log.Printf("begin stream %08x:%d", conv, stream.ID())

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		_, err := io.Copy(stream, local)
		if err == io.EOF {
			err = nil
		}
		if err != nil && !errors.Is(err, io.ErrClosedPipe) {
			log.Printf("stream %08x:%d copy stream←local: %v", conv, stream.ID(), err)
		}
		local.CloseRead()
		stream.Close()
	}()
	go func() {
		defer wg.Done()
		_, err := io.Copy(local, stream)
		if err == io.EOF {
			err = nil
		}
		if err != nil && !errors.Is(err, io.ErrClosedPipe) {
			log.Printf("stream %08x:%d copy local←stream: %v", conv, stream.ID(), err)
		}
		local.CloseWrite()
		if err != nil {
			local.CloseRead()
		}
	}()
	wg.Wait()

	return nil
}

// handleWithAuth intercepts the SOCKS5 handshake, injects the server credentials
// transparently, and tells the client no authentication is needed. This means
// browsers and tools connect to 127.0.0.1:PORT with no credentials regardless
// of whether the server requires username/password auth.
func handleWithAuth(local *net.TCPConn, sess *smux.Session, conv uint32, socksUser, socksPass string) error {
	// Read client greeting: [VER NMETHODS METHODS...]
	header := make([]byte, 2)
	if _, err := io.ReadFull(local, header); err != nil {
		return err
	}
	if header[0] != 5 {
		return fmt.Errorf("not SOCKS5 (ver=%d)", header[0])
	}
	methods := make([]byte, int(header[1]))
	if len(methods) > 0 {
		if _, err := io.ReadFull(local, methods); err != nil {
			return err
		}
	}

	// Open smux stream to server.
	stream, err := sess.OpenStream()
	if err != nil {
		local.Write([]byte{5, 1, 0, 1, 0, 0, 0, 0, 0, 0})
		return fmt.Errorf("session %08x opening stream: %v", conv, err)
	}
	defer func() {
		log.Printf("end stream %08x:%d (auth)", conv, stream.ID())
		stream.Close()
	}()
	log.Printf("begin stream %08x:%d (auth)", conv, stream.ID())

	// Offer the server both no-auth and user/pass so we handle either case.
	if _, err := stream.Write([]byte{5, 2, 0x00, 0x02}); err != nil {
		local.Write([]byte{5, 1, 0, 1, 0, 0, 0, 0, 0, 0})
		return err
	}
	serverChoice := make([]byte, 2)
	if _, err := io.ReadFull(stream, serverChoice); err != nil {
		local.Write([]byte{5, 1, 0, 1, 0, 0, 0, 0, 0, 0})
		return fmt.Errorf("reading server auth choice: %v", err)
	}
	switch serverChoice[1] {
	case 0x00:
		// Server is happy with no auth — nothing to do.
	case 0x02:
		// Server requires user/pass — inject credentials from profile.
		authMsg := []byte{0x01, byte(len(socksUser))}
		authMsg = append(authMsg, []byte(socksUser)...)
		authMsg = append(authMsg, byte(len(socksPass)))
		authMsg = append(authMsg, []byte(socksPass)...)
		if _, err := stream.Write(authMsg); err != nil {
			local.Write([]byte{5, 1, 0, 1, 0, 0, 0, 0, 0, 0})
			return err
		}
		authResp := make([]byte, 2)
		if _, err := io.ReadFull(stream, authResp); err != nil || authResp[1] != 0 {
			local.Write([]byte{5, 1, 0, 1, 0, 0, 0, 0, 0, 0})
			return fmt.Errorf("SOCKS5 auth rejected by server")
		}
	default:
		local.Write([]byte{5, 1, 0, 1, 0, 0, 0, 0, 0, 0})
		return fmt.Errorf("server rejected all auth methods (0x%02x)", serverChoice[1])
	}

	// Tell the client: no authentication required.
	if _, err := local.Write([]byte{5, 0}); err != nil {
		return err
	}

	// Read client CONNECT request: [VER CMD RSV ATYP ...] and forward to server.
	reqFixed := make([]byte, 4)
	if _, err := io.ReadFull(local, reqFixed); err != nil {
		return err
	}
	if _, err := stream.Write(reqFixed); err != nil {
		return err
	}
	switch reqFixed[3] {
	case 0x01: // IPv4 (4) + port (2)
		buf := make([]byte, 6)
		if _, err := io.ReadFull(local, buf); err != nil {
			return err
		}
		stream.Write(buf)
	case 0x03: // domain: len(1) + domain + port(2)
		lenB := make([]byte, 1)
		if _, err := io.ReadFull(local, lenB); err != nil {
			return err
		}
		stream.Write(lenB)
		rest := make([]byte, int(lenB[0])+2)
		if _, err := io.ReadFull(local, rest); err != nil {
			return err
		}
		stream.Write(rest)
	case 0x04: // IPv6 (16) + port (2)
		buf := make([]byte, 18)
		if _, err := io.ReadFull(local, buf); err != nil {
			return err
		}
		stream.Write(buf)
	default:
		return fmt.Errorf("unsupported ATYP: %d", reqFixed[3])
	}

	// Forward server CONNECT response to client.
	respFixed := make([]byte, 4)
	if _, err := io.ReadFull(stream, respFixed); err != nil {
		return err
	}
	local.Write(respFixed)
	switch respFixed[3] {
	case 0x01:
		buf := make([]byte, 6)
		io.ReadFull(stream, buf)
		local.Write(buf)
	case 0x03:
		lenB := make([]byte, 1)
		io.ReadFull(stream, lenB)
		local.Write(lenB)
		rest := make([]byte, int(lenB[0])+2)
		io.ReadFull(stream, rest)
		local.Write(rest)
	case 0x04:
		buf := make([]byte, 18)
		io.ReadFull(stream, buf)
		local.Write(buf)
	}
	if respFixed[1] != 0 {
		return fmt.Errorf("CONNECT failed: rep=0x%02x", respFixed[1])
	}

	// Relay data bidirectionally.
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		_, err := io.Copy(stream, local)
		if err != nil && err != io.EOF && !errors.Is(err, io.ErrClosedPipe) {
			log.Printf("stream %08x:%d copy stream←local: %v", conv, stream.ID(), err)
		}
		local.CloseRead()
		stream.Close()
	}()
	go func() {
		defer wg.Done()
		_, err := io.Copy(local, stream)
		if err != nil && err != io.EOF && !errors.Is(err, io.ErrClosedPipe) {
			log.Printf("stream %08x:%d copy local←stream: %v", conv, stream.ID(), err)
		}
		local.CloseWrite()
	}()
	wg.Wait()

	return nil
}

// utlsDialContext connects to addr and performs a uTLS handshake.
func utlsDialContext(ctx context.Context, network, addr string, config *utls.Config, id *utls.ClientHelloID) (*utls.UConn, error) {
	if config == nil {
		config = &utls.Config{}
	}
	if config.ServerName == "" {
		config = config.Clone()
		host, _, err := net.SplitHostPort(addr)
		if err != nil {
			return nil, err
		}
		config.ServerName = host
	}
	conn, err := (&net.Dialer{}).DialContext(ctx, network, addr)
	if err != nil {
		return nil, err
	}
	uconn := utls.UClient(conn, config, *id)
	err = uconn.Handshake()
	if err != nil {
		uconn.Close()
		return nil, err
	}
	return uconn, nil
}

// addrForDial extracts a host:port address from a URL.
func addrForDial(u *url.URL) (string, error) {
	host := u.Hostname()
	port := u.Port()
	if port == "" {
		switch u.Scheme {
		case "http":
			port = "80"
		case "https":
			port = "443"
		default:
			return "", fmt.Errorf("unsupported URL scheme %q", u.Scheme)
		}
	}
	return net.JoinHostPort(host, port), nil
}

// socks5UTLSRoundTripper is an http.RoundTripper that uses uTLS for TLS
// connections routed through a SOCKS5 proxy.
type socks5UTLSRoundTripper struct {
	clientHelloID *utls.ClientHelloID
	config        *utls.Config
	innerLock     sync.Mutex
	inner         http.RoundTripper
}

func (rt *socks5UTLSRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	switch req.URL.Scheme {
	case "http":
		return http.DefaultTransport.RoundTrip(req)
	case "https":
	default:
		return nil, fmt.Errorf("unsupported URL scheme %q", req.URL.Scheme)
	}

	var err error
	rt.innerLock.Lock()
	if rt.inner == nil {
		rt.inner, err = rt.makeRoundTripper(req)
	}
	rt.innerLock.Unlock()
	if err != nil {
		return nil, err
	}
	return rt.inner.RoundTrip(req)
}

func (rt *socks5UTLSRoundTripper) makeRoundTripper(req *http.Request) (http.RoundTripper, error) {
	addr, err := addrForDial(req.URL)
	if err != nil {
		return nil, err
	}

	bootstrapConn, err := utlsDialContext(req.Context(), "tcp", addr, rt.config, rt.clientHelloID)
	if err != nil {
		return nil, err
	}

	protocol := bootstrapConn.ConnectionState().NegotiatedProtocol

	var lock sync.Mutex
	dialTLS := func(ctx context.Context, network, addr string) (net.Conn, error) {
		lock.Lock()
		defer lock.Unlock()

		if bootstrapConn != nil {
			uconn := bootstrapConn
			bootstrapConn = nil
			return uconn, nil
		}

		uconn, err := utlsDialContext(ctx, "tcp", addr, rt.config, rt.clientHelloID)
		if err != nil {
			return nil, err
		}
		if uconn.ConnectionState().NegotiatedProtocol != protocol {
			return nil, fmt.Errorf("unexpected switch from ALPN %q to %q",
				protocol, uconn.ConnectionState().NegotiatedProtocol)
		}
		return uconn, nil
	}

	switch protocol {
	case http2.NextProtoTLS:
		return &http2.Transport{
			DialTLS: func(network, addr string, _ *tls.Config) (net.Conn, error) {
				return dialTLS(context.Background(), network, addr)
			},
		}, nil
	default:
		tr := http.DefaultTransport.(*http.Transport).Clone()
		tr.DialTLSContext = dialTLS
		return tr, nil
	}
}
