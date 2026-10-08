package outbound

import (
	"context"
	"strings"
	"testing"

	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/transport/socks5s"
)

// socks5sTestKeyPair produces a credential the outbound accepts, so the tests
// exercise the rejection paths rather than the key parser.
func socks5sTestKeyPair() (seed string, public string, err error) {
	s, p, err := socks5s.GenerateKeyPairForTest()
	if err != nil {
		return "", "", err
	}
	return s, p, nil
}

// metadataFor builds a minimal destination.
func metadataFor(host string, port uint16) *C.Metadata {
	return &C.Metadata{Host: host, DstPort: port}
}

// TestNewSocks5sRejectsInvalidOptions pins the construction checks, so a bad
// configuration fails at load with a precise message.
func TestNewSocks5sRejectsInvalidOptions(t *testing.T) {
	for _, tc := range []struct {
		name   string
		option Socks5sOption
		want   string
	}{
		{
			name:   "no server",
			option: Socks5sOption{Name: "a", Port: 443, Encryption: "x"},
			want:   "valid server and port",
		},
		{
			name:   "no port",
			option: Socks5sOption{Name: "a", Server: "example.com", Encryption: "x"},
			want:   "valid server and port",
		},
		{
			name:   "port out of range",
			option: Socks5sOption{Name: "a", Server: "example.com", Port: 65536, Encryption: "x"},
			want:   "valid server and port",
		},
		{
			name:   "no encryption",
			option: Socks5sOption{Name: "a", Server: "example.com", Port: 443},
			want:   "requires an encryption key",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := NewSocks5s(tc.option)
			if err == nil {
				t.Fatal("expected an error")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error %q does not mention %q", err, tc.want)
			}
		})
	}
}

// TestNewSocks5sForcesUDPOff pins that the TCP-only nature of the protocol
// cannot be overridden by configuration: the reference answers UDP ASSOCIATE
// with "command not supported", so advertising UDP would break connections
// rather than enable them.
func TestNewSocks5sForcesUDPOff(t *testing.T) {
	seed, public, err := socks5sTestKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	_ = seed

	outbound, err := NewSocks5s(Socks5sOption{
		Name:       "udp-attempt",
		Server:     "example.com",
		Port:       443,
		Encryption: public,
		UDP:        true,
	})
	if err != nil {
		t.Fatalf("NewSocks5s: %v", err)
	}
	if outbound.SupportUDP() {
		t.Fatal("UDP must stay off: the protocol has no UDP path")
	}
}

// TestSocks5sListenPacketUnsupported pins the sentinel error, which is what lets
// the rule engine reject knowingly instead of reporting a transport fault.
func TestSocks5sListenPacketUnsupported(t *testing.T) {
	_, public, err := socks5sTestKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	outbound, err := NewSocks5s(Socks5sOption{
		Name:       "no-udp",
		Server:     "example.com",
		Port:       443,
		Encryption: public,
	})
	if err != nil {
		t.Fatalf("NewSocks5s: %v", err)
	}
	if _, err := outbound.ListenPacketContext(context.Background(), nil); err != C.ErrNotSupport {
		t.Fatalf("ListenPacketContext returned %v, want the not-supported sentinel", err)
	}
}

// TestSocks5sRejectsMalformedEncryption proves a bad key fails the dial rather
// than making the whole configuration unloadable, and that the message names
// the problem.
func TestSocks5sRejectsMalformedEncryption(t *testing.T) {
	outbound, err := NewSocks5s(Socks5sOption{
		Name:       "bad-key",
		Server:     "example.com",
		Port:       443,
		Encryption: "not-a-key",
	})
	if err != nil {
		t.Fatalf("construction should succeed so one bad key cannot reject the config: %v", err)
	}
	_, err = outbound.DialContext(context.Background(), metadataFor("example.org", 80))
	if err == nil {
		t.Fatal("expected the dial to fail on a malformed key")
	}
	if !strings.Contains(err.Error(), "dot-separated") {
		t.Fatalf("error should describe the key format, got: %v", err)
	}
}
