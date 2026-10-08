// Package socks5s implements the client half of the socks5s tunnel: a SOCKS5
// proxy carried over a self-contained post-quantum encrypted stream.
//
// The reference implementation is the Go project `socks5s` (v4.0.0) shipped
// alongside this port. This package reproduces its wire format byte for byte so
// a FlClash client interoperates with an unmodified socks5s server; only the
// client role is implemented, because FlClash never terminates the tunnel.
//
// Two departures from the reference are forced by the host module:
//
//   - crypto/mlkem and crypto/hkdf are Go 1.24 standard library packages, while
//     mihomo declares go 1.20. They are replaced by github.com/metacubex/mlkem
//     and golang.org/x/crypto/hkdf, both already dependencies. The ML-KEM-768
//     wire sizes were verified to match the reference exactly.
//   - The reference resolves and dials targets itself; here the caller supplies
//     the connection so mihomo's dialer options apply.
package socks5s

import (
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"github.com/metacubex/mlkem"
)

// The credential is one self-describing string:
//
//	mlkem768x25519.native.<base64url>
//	│              │       └── key material, distinguished by decoded length
//	│              └────────── traffic appearance
//	└───────────────────────── handshake algorithm
//
// The key block carries the role by length, so no tagging scheme is needed:
//
//	64 bytes   ML-KEM-768 decapsulation seed    server side
//	1184 bytes ML-KEM-768 encapsulation key     client side
//
// FlClash is a client, so only the second form is usable here, but the seed
// form is still parsed so that pasting a server key produces an explanation
// instead of a length error.
const (
	keyAlgorithm  = "mlkem768x25519"
	keyModeNative = "native"

	// seedLen and encapsulationLen mirror mlkem.SeedSize and
	// mlkem.EncapsulationKeySize768 without going through the constants, so a
	// future dependency bump cannot silently change the wire format.
	seedLen          = 64
	encapsulationLen = 1184

	// x25519Len is the size of an X25519 public key or shared secret.
	x25519Len = 32

	// sharedKeyLen is the size of an ML-KEM shared secret.
	sharedKeyLen = 32
)

// keyString is a parsed credential.
type keyString struct {
	mode string
	raw  []byte
}

// parseKey decodes a credential string.
//
// Exactly three blocks are accepted. The reference implements only the static
// and ephemeral layers, so the blocks the Xray format adds after the key —
// session resumption ("600s", "0rtt") and padding/delay — are rejected rather
// than ignored: silently accepting "600s" would advertise a 0-RTT handshake
// this build never performs.
func parseKey(s string) (*keyString, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, errors.New("socks5s: key is empty")
	}
	blocks := strings.Split(s, ".")

	switch {
	case len(blocks) < 3:
		return nil, fmt.Errorf(
			"socks5s: key has %d dot-separated blocks, want 3 (algorithm.mode.key)",
			len(blocks))
	case len(blocks) > 3:
		return nil, fmt.Errorf(
			"socks5s: key has %d blocks; the Xray-format blocks after the key (%q) are not implemented.\n"+
				"  a session-resumption block (600s, 0rtt) would promise 0-RTT: every handshake here is a full one\n"+
				"  padding/delay blocks are traffic shaping: not implemented either\n"+
				"  use exactly: %s.%s.<key>",
			len(blocks), strings.Join(blocks[2:], "."), keyAlgorithm, keyModeNative)
	}

	if blocks[0] != keyAlgorithm {
		return nil, fmt.Errorf("socks5s: unsupported handshake algorithm %q, want %q",
			blocks[0], keyAlgorithm)
	}
	if blocks[1] != keyModeNative {
		return nil, fmt.Errorf("socks5s: unknown traffic mode %q, want %q", blocks[1], keyModeNative)
	}

	raw, err := base64.RawURLEncoding.DecodeString(blocks[2])
	if err != nil {
		// Accept the padded alphabet too, since keys get pasted by hand.
		raw, err = base64.URLEncoding.DecodeString(blocks[2])
		if err != nil {
			return nil, fmt.Errorf("socks5s: key block is not base64url: %w", err)
		}
	}

	switch len(raw) {
	case seedLen, encapsulationLen:
	default:
		return nil, fmt.Errorf(
			"socks5s: key block decodes to %d bytes; want %d (server seed) or %d (client public key)",
			len(raw), seedLen, encapsulationLen)
	}
	return &keyString{mode: blocks[1], raw: raw}, nil
}

// role names which half of an identity this credential is.
func (k *keyString) role() string {
	if len(k.raw) == seedLen {
		return "server"
	}
	return "client"
}

// clientKey returns the peer's encapsulation key.
//
// A server seed reaches this path whenever someone pastes the wrong half of the
// pair; saying so is more useful than the length error the KEM would raise.
func (k *keyString) clientKey() (*mlkem.EncapsulationKey768, error) {
	if len(k.raw) != encapsulationLen {
		return nil, fmt.Errorf(
			"socks5s: this is a %s key; the client needs the %d byte public key derived from the server seed, not the seed itself",
			k.role(), encapsulationLen)
	}
	return mlkem.NewEncapsulationKey768(k.raw)
}

// newEncapsulationKey parses a client credential, creating the AEAD key used to
// encrypt traffic to the server.
func newEncapsulationKey(s string) (*mlkem.EncapsulationKey768, error) {
	k, err := parseKey(s)
	if err != nil {
		return nil, err
	}
	return k.clientKey()
}

// generateKeyPair produces one identity: the seed a server keeps and the public
// key its clients are given. It exists so tests and tooling do not have to
// reach for the KEM directly.
func generateKeyPair() (seed, public []byte, err error) {
	dk, err := mlkem.GenerateKey768()
	if err != nil {
		return nil, nil, err
	}
	return dk.Bytes(), dk.EncapsulationKey().Bytes(), nil
}

// publicFromSeed derives the client half of a server identity, so a server can
// hand out its public key without regenerating the pair.
func publicFromSeed(seed []byte) ([]byte, error) {
	dk, err := mlkem.NewDecapsulationKey768(seed)
	if err != nil {
		return nil, err
	}
	return dk.EncapsulationKey().Bytes(), nil
}

// encodeKey renders key material in the credential format.
func encodeKey(raw []byte) string {
	return keyAlgorithm + "." + keyModeNative + "." + base64.RawURLEncoding.EncodeToString(raw)
}

// GenerateKeyPairForTest returns one identity as credential strings: the seed a
// server keeps and the public key its clients are given.
//
// It exists for tests in other packages that need a well-formed credential, and
// is named accordingly so it is not mistaken for an operational API. Real key
// material is produced by the socks5s server, not by a client.
func GenerateKeyPairForTest() (seed string, public string, err error) {
	s, p, err := generateKeyPair()
	if err != nil {
		return "", "", err
	}
	return encodeKey(s), encodeKey(p), nil
}
