package vaydns

import (
	"strings"
	"testing"
)

func TestCreateUDPTransport_RejectsEmptyHost(t *testing.T) {
	bad := []string{":53", "", ",:53", ":"}
	for _, addr := range bad {
		c := &VaydnsClient{dnsAddr: addr}
		_, _, err := c.createUDPTransport()
		if err == nil {
			t.Errorf("createUDPTransport(%q): expected error for missing host, got nil", addr)
		} else if !strings.Contains(err.Error(), "missing a host") {
			t.Errorf("createUDPTransport(%q): unexpected error: %v", addr, err)
		}
	}
}
