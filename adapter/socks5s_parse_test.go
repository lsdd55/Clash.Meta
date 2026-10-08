package adapter

import (
	"testing"

	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/transport/socks5s"
)

// TestParseProxySocks5s proves the protocol is reachable through the ordinary
// configuration path, which is what makes it usable from a profile at all.
func TestParseProxySocks5s(t *testing.T) {
	_, public, err := socks5s.GenerateKeyPairForTest()
	if err != nil {
		t.Fatalf("key pair: %v", err)
	}

	proxy, err := ParseProxy(map[string]any{
		"name":       "my-socks5s",
		"type":       "socks5s",
		"server":     "example.com",
		"port":       62330,
		"encryption": public,
	})
	if err != nil {
		t.Fatalf("ParseProxy: %v", err)
	}
	if proxy == nil {
		t.Fatal("ParseProxy returned nil")
	}
	if got := proxy.Type(); got != C.Socks5s {
		t.Fatalf("type is %v (%s), want %v (Socks5s)", got, got, C.Socks5s)
	}
	if got := proxy.Name(); got != "my-socks5s" {
		t.Fatalf("name is %q, want my-socks5s", got)
	}
	// The protocol has no UDP path, so the adapter must not advertise it.
	if info := proxy.ProxyInfo(); info.XUDP {
		t.Fatal("Socks5s must not advertise UDP support")
	}
	if proxy.SupportUDP() {
		t.Fatal("Socks5s must not support UDP")
	}
}

// TestParseProxySocks5sRequiresKey pins that omitting the credential is
// rejected at parse time rather than producing an outbound that fails on every
// connection.
func TestParseProxySocks5sRequiresKey(t *testing.T) {
	_, err := ParseProxy(map[string]any{
		"name":   "no-key",
		"type":   "socks5s",
		"server": "example.com",
		"port":   62330,
	})
	if err == nil {
		t.Fatal("expected a missing-key error")
	}
}

// TestAdapterTypeStringSocks5s pins the display string, which the UI and the
// type filter both read.
func TestAdapterTypeStringSocks5s(t *testing.T) {
	if got := C.Socks5s.String(); got != "Socks5s" {
		t.Fatalf("AdapterType String() is %q, want Socks5s", got)
	}
}
