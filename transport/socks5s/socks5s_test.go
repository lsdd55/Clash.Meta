package socks5s

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"io"
	"net"
	"strings"
	"testing"

	"github.com/metacubex/mlkem"
	"golang.org/x/crypto/hkdf"
)

// base64URLPadded renders key material with padding, the shape a hand-pasted
// key sometimes carries.
func base64URLPadded(raw []byte) string {
	return base64.URLEncoding.EncodeToString(raw)
}

// TestHKDFMatchesRFC5869 pins hkdfKey against the RFC 5869 Test Case 1 vector.
//
// The reference implementation calls the Go 1.24 standard library's
// crypto/hkdf.Key, which this module cannot use because mihomo declares go
// 1.20. This test is what makes the golang.org/x/crypto substitution safe: if
// the two ever disagreed, every session key would differ from the reference and
// nothing would interoperate.
func TestHKDFMatchesRFC5869(t *testing.T) {
	ikm, _ := hex.DecodeString("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b")
	salt, _ := hex.DecodeString("000102030405060708090a0b0c")
	infoBytes, _ := hex.DecodeString("f0f1f2f3f4f5f6f7f8f9")
	info := string(infoBytes)
	want := "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"

	got, err := hkdfKey(ikm, salt, info, 42)
	if err != nil {
		t.Fatalf("hkdfKey: %v", err)
	}
	if hex.EncodeToString(got) != want {
		t.Fatalf("RFC 5869 TC1 mismatch\n got: %x\nwant: %s", got, want)
	}
}

// TestHKDFKeyMatchesReaderForm proves the helper is exactly
// hkdf.New(...).Read(...) with no extra framing.
func TestHKDFKeyMatchesReaderForm(t *testing.T) {
	secret := []byte("0123456789abcdef0123456789abcdef")
	salt := []byte("0011223344556677")

	got, err := hkdfKey(secret, salt, "qxproxy v1", 64)
	if err != nil {
		t.Fatalf("hkdfKey: %v", err)
	}
	r := hkdf.New(sha256.New, secret, salt, []byte("qxproxy v1"))
	want := make([]byte, 64)
	if _, err := r.Read(want); err != nil {
		t.Fatalf("read: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatal("hkdfKey diverges from hkdf.New(...).Read(...)")
	}
}

// TestParseKeyAcceptsClientPublicKey covers the only credential shape a FlClash
// client may use.
func TestParseKeyAcceptsClientPublicKey(t *testing.T) {
	_, public, err := generateKeyPair()
	if err != nil {
		t.Fatalf("generateKeyPair: %v", err)
	}
	if len(public) != encapsulationLen {
		t.Fatalf("public key is %d bytes, want %d", len(public), encapsulationLen)
	}

	k, err := parseKey(encodeKey(public))
	if err != nil {
		t.Fatalf("parseKey: %v", err)
	}
	if k.role() != "client" {
		t.Fatalf("role is %q, want client", k.role())
	}
	if _, err := k.clientKey(); err != nil {
		t.Fatalf("clientKey: %v", err)
	}
}

// TestParseKeyRejectsServerSeedWithExplanation pins the failure a user sees when
// they paste the wrong half of the pair. It must name the mistake, not report a
// length.
func TestParseKeyRejectsServerSeedWithExplanation(t *testing.T) {
	seed, _, err := generateKeyPair()
	if err != nil {
		t.Fatalf("generateKeyPair: %v", err)
	}

	k, err := parseKey(encodeKey(seed))
	if err != nil {
		t.Fatalf("parseKey should accept the seed shape: %v", err)
	}
	if k.role() != "server" {
		t.Fatalf("role is %q, want server", k.role())
	}

	_, err = k.clientKey()
	if err == nil {
		t.Fatal("clientKey accepted a server seed")
	}
	if !strings.Contains(err.Error(), "server key") {
		t.Fatalf("error should explain the wrong half was pasted, got: %v", err)
	}
}

// TestParseKeyRejectsXrayExtraBlocks pins decision D1: the extra blocks the Xray
// format defines are refused rather than ignored, because accepting "600s" would
// advertise a 0-RTT handshake this build never performs.
func TestParseKeyRejectsXrayExtraBlocks(t *testing.T) {
	_, public, err := generateKeyPair()
	if err != nil {
		t.Fatalf("generateKeyPair: %v", err)
	}
	body := strings.TrimPrefix(encodeKey(public), keyAlgorithm+"."+keyModeNative+".")

	for _, tc := range []struct {
		name string
		key  string
	}{
		{"session resumption", keyAlgorithm + "." + keyModeNative + ".600s." + body},
		{"0rtt", keyAlgorithm + "." + keyModeNative + ".0rtt." + body},
		{"padding block", keyAlgorithm + "." + keyModeNative + ".100-111-1111." + body},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := parseKey(tc.key)
			if err == nil {
				t.Fatal("expected rejection")
			}
			if !strings.Contains(err.Error(), "not implemented") {
				t.Fatalf("error should say the block is not implemented, got: %v", err)
			}
		})
	}
}

// TestParseKeyRejectsMalformed covers the shapes a typo produces.
func TestParseKeyRejectsMalformed(t *testing.T) {
	_, public, err := generateKeyPair()
	if err != nil {
		t.Fatalf("generateKeyPair: %v", err)
	}
	body := strings.TrimPrefix(encodeKey(public), keyAlgorithm+"."+keyModeNative+".")

	for _, tc := range []struct {
		name string
		key  string
	}{
		{"empty", ""},
		{"whitespace", "   "},
		{"two blocks", keyAlgorithm + "." + keyModeNative},
		{"wrong algorithm", "mlkem768x25519plus." + keyModeNative + "." + body},
		{"wrong mode", keyAlgorithm + ".xorpub." + body},
		{"bad base64", keyAlgorithm + "." + keyModeNative + ".!!!not-base64!!!"},
		{"short key", keyAlgorithm + "." + keyModeNative + ".AAAA"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := parseKey(tc.key); err == nil {
				t.Fatal("expected rejection")
			}
		})
	}
}

// TestParseKeyAcceptsPaddedBase64 covers pasted keys that carry padding.
func TestParseKeyAcceptsPaddedBase64(t *testing.T) {
	_, public, err := generateKeyPair()
	if err != nil {
		t.Fatalf("generateKeyPair: %v", err)
	}
	raw, err := parseKey(encodeKey(public))
	if err != nil {
		t.Fatalf("parseKey: %v", err)
	}
	padded := keyAlgorithm + "." + keyModeNative + "." +
		base64URLPadded(raw.raw)
	if _, err := parseKey(padded); err != nil {
		t.Fatalf("padded base64 should be accepted: %v", err)
	}
}

// TestPublicFromSeedMatchesGeneratedPair pins that the seed round trip yields
// the same identity, which is what lets a server publish only its public key.
func TestPublicFromSeedMatchesGeneratedPair(t *testing.T) {
	seed, public, err := generateKeyPair()
	if err != nil {
		t.Fatalf("generateKeyPair: %v", err)
	}
	derived, err := publicFromSeed(seed)
	if err != nil {
		t.Fatalf("publicFromSeed: %v", err)
	}
	if !bytes.Equal(derived, public) {
		t.Fatal("publicFromSeed diverges from the generated public key")
	}
}

// TestMLKEMConstantsMatchWireFormat pins the sizes the handshake hardcodes
// against the dependency, so a dependency bump that changed them fails here
// instead of producing a stream the reference cannot read.
func TestMLKEMConstantsMatchWireFormat(t *testing.T) {
	if mlkem.EncapsulationKeySize768 != encapsulationLen {
		t.Fatalf("EncapsulationKeySize768 is %d, package assumes %d",
			mlkem.EncapsulationKeySize768, encapsulationLen)
	}
	if mlkem.CiphertextSize768 != mlkemCiphertextLen {
		t.Fatalf("CiphertextSize768 is %d, package assumes %d",
			mlkem.CiphertextSize768, mlkemCiphertextLen)
	}
	if mlkem.SeedSize != seedLen {
		t.Fatalf("SeedSize is %d, package assumes %d", mlkem.SeedSize, seedLen)
	}
	if mlkem.SharedKeySize != sharedKeyLen {
		t.Fatalf("SharedKeySize is %d, package assumes %d", mlkem.SharedKeySize, sharedKeyLen)
	}
}

// TestHandshakeFlightSizes pins the greeting and response sizes. The reference
// documents 2341 and 1141; the server reads a fixed length for the greeting
// prefix, so a mismatch here means no connection can complete.
func TestHandshakeFlightSizes(t *testing.T) {
	if msg1PrefiLen := ivLen + mlkemCiphertextLen; msg1PrefiLen != 1104 {
		t.Fatalf("greeting prefix is %d, want 1104", msg1PrefiLen)
	}
	if pfsPubSize != 1216 {
		t.Fatalf("ephemeral material is %d, want 1216", pfsPubSize)
	}
	if msg2PayloadSize != 1120 {
		t.Fatalf("response payload is %d, want 1120", msg2PayloadSize)
	}
	if msg1Size != 2341 {
		t.Fatalf("greeting is %d, want 2341", msg1Size)
	}
	if msg2Size != 1141 {
		t.Fatalf("response is %d, want 1141", msg2Size)
	}
}

// TestRecordLayerRoundTrip drives an established SecureConn through the shapes
// the data path actually uses.
func TestRecordLayerRoundTrip(t *testing.T) {
	keyA := make([]byte, 32)
	keyB := make([]byte, 32)
	if _, err := rand.Read(keyA); err != nil {
		t.Fatal(err)
	}
	if _, err := rand.Read(keyB); err != nil {
		t.Fatal(err)
	}

	clientPipe, serverPipe := net.Pipe()
	defer clientPipe.Close()
	defer serverPipe.Close()

	client, err := newSecureConn(clientPipe, keyA, keyB)
	if err != nil {
		t.Fatalf("client: %v", err)
	}
	server, err := newSecureConn(serverPipe, keyB, keyA)
	if err != nil {
		t.Fatalf("server: %v", err)
	}

	payloads := [][]byte{
		[]byte("small"),
		bytes.Repeat([]byte("a"), 100),
		bytes.Repeat([]byte("b"), maxPlaintext),
		bytes.Repeat([]byte("c"), maxPlaintext+1),
		bytes.Repeat([]byte("d"), 3*maxPlaintext+7),
	}

	for i, want := range payloads {
		got := make([]byte, len(want))
		done := make(chan error, 1)
		go func() {
			_, err := client.Write(want)
			done <- err
		}()
		if _, err := io.ReadFull(server, got); err != nil {
			t.Fatalf("payload %d: read: %v", i, err)
		}
		if err := <-done; err != nil {
			t.Fatalf("payload %d: write: %v", i, err)
		}
		if !bytes.Equal(got, want) {
			t.Fatalf("payload %d: round trip mismatch (%d bytes)", i, len(want))
		}
	}
}

// TestRecordLayerRejectsTamperedRecord proves the header is authenticated: the
// length field is additional data, so flipping it must fail the open.
func TestRecordLayerRejectsTamperedRecord(t *testing.T) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	state, err := newAEADState(key)
	if err != nil {
		t.Fatal(err)
	}
	rec, err := (&SecureConn{send: state}).sealTo(nil, []byte("hello"))
	if err != nil {
		t.Fatal(err)
	}

	tampered := append([]byte(nil), rec...)
	tampered[recordHeaderSize] ^= 0x01

	recvState, err := newAEADState(key)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := openRecord(bytes.NewReader(tampered), recvState.aead, zeroNonce); err == nil {
		t.Fatal("a tampered record was accepted")
	}
}

// TestSecureConnReadsShortBuffer covers the slow path, where the caller's buffer
// is smaller than one record.
func TestSecureConnReadsShortBuffer(t *testing.T) {
	keyA := make([]byte, 32)
	keyB := make([]byte, 32)
	if _, err := rand.Read(keyA); err != nil {
		t.Fatal(err)
	}
	if _, err := rand.Read(keyB); err != nil {
		t.Fatal(err)
	}

	clientPipe, serverPipe := net.Pipe()
	defer clientPipe.Close()
	defer serverPipe.Close()

	client, err := newSecureConn(clientPipe, keyA, keyB)
	if err != nil {
		t.Fatal(err)
	}
	server, err := newSecureConn(serverPipe, keyB, keyA)
	if err != nil {
		t.Fatal(err)
	}

	want := bytes.Repeat([]byte("z"), 200)
	go client.Write(want)

	var got []byte
	buf := make([]byte, 7)
	for len(got) < len(want) {
		n, err := server.Read(buf)
		if err != nil {
			t.Fatalf("read: %v", err)
		}
		got = append(got, buf[:n]...)
	}
	if !bytes.Equal(got, want) {
		t.Fatal("short buffer read mismatch")
	}
}
