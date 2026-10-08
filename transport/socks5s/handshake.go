package socks5s

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"net"

	"github.com/metacubex/mlkem"
	"golang.org/x/crypto/hkdf"
)

// The handshake runs a static layer and an ephemeral layer on top of it.
//
//	static layer (not forward secret): the client encapsulates to the server's
//	  long-term ML-KEM-768 key. Only the real server can decapsulate, which
//	  authenticates it, post-quantum.
//
//	ephemeral layer (forward secret): carried inside the static layer. The
//	  client sends a fresh ML-KEM-768 encapsulation key and a fresh X25519
//	  public key; the server encapsulates to both. Both halves are ephemeral,
//	  so the session key survives a later compromise of the long-term key.
//
// The session key mixes BOTH layers, so decrypting a recorded session needs the
// long-term ML-KEM-768 key AND the ephemeral exchange broken; neither alone
// suffices.
//
// Handshake wire sizes. Every field is fixed length, so each side reads and
// writes one flight and there is no length negotiation.
const (
	// pfsPubSize is the client's ephemeral material: an X25519 public key
	// followed by an ML-KEM-768 encapsulation key.
	pfsPubSize = x25519Len + encapsulationLen // 1216

	// msg1PrefixLen is the fixed part of the client greeting the server must
	// read before it can decapsulate: iv || static layer ciphertext.
	msg1PrefixLen = ivLen + mlkemCiphertextLen // 1104

	// msg2PayloadSize is the server's ephemeral material.
	msg2PayloadSize = mlkemCiphertextLen + x25519Len // 1120

	// msg1Size is the framed client greeting.
	msg1Size = msg1PrefixLen + recordHeaderSize + pfsPubSize + recordTagLen // 2341

	// msg2Size is the framed server response.
	msg2Size = recordHeaderSize + msg2PayloadSize + recordTagLen // 1141

	// mlkemCiphertextLen is the ML-KEM-768 ciphertext size, restated here so
	// the wire format is pinned independently of the dependency.
	mlkemCiphertextLen = 1088

	// masterKeyLen is 32 bytes per direction.
	masterKeyLen = 64
)

// errAuth marks any handshake failure. Callers must not distinguish between its
// causes when talking to the peer.
var errAuth = errors.New("socks5s: handshake authentication failed")

// ClientHandshake performs the client half of the socks5s handshake in a single
// round trip and returns the established encrypted stream.
//
// The greeting deliberately carries no application data. Anything sent here
// travels under the static layer key, which is neither forward secret nor
// replay resistant, so a recorded greeting could be replayed to make the server
// act on it. The caller sends its request frame over the returned connection
// instead, which is what TLS 1.3 and Xray do as well.
func ClientHandshake(conn net.Conn, encryption string) (*SecureConn, error) {
	ek, err := newEncapsulationKey(encryption)
	if err != nil {
		return nil, err
	}
	return clientHandshake(conn, ek)
}

func clientHandshake(conn net.Conn, ek *mlkem.EncapsulationKey768) (*SecureConn, error) {
	iv := make([]byte, ivLen)
	if _, err := rand.Read(iv); err != nil {
		return nil, err
	}

	// Static layer. Encapsulate returns (sharedKey, ciphertext).
	nfsSS, pqCt := ek.Encapsulate()
	if len(pqCt) != mlkemCiphertextLen {
		return nil, fmt.Errorf("%w: unexpected ciphertext length %d", errAuth, len(pqCt))
	}
	c2sNFS, s2cNFS, err := deriveNFS(nfsSS, iv)
	if err != nil {
		return nil, err
	}
	c2sAEAD, err := gcm(c2sNFS)
	if err != nil {
		return nil, err
	}
	s2cAEAD, err := gcm(s2cNFS)
	if err != nil {
		return nil, err
	}

	// Ephemeral layer: a fresh ML-KEM-768 key pair and a fresh X25519 key pair.
	px, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	pfsKey, err := mlkem.GenerateKey768()
	if err != nil {
		return nil, err
	}

	inner := make([]byte, 0, pfsPubSize)
	inner = append(inner, px.PublicKey().Bytes()...)
	inner = append(inner, pfsKey.EncapsulationKey().Bytes()...)

	msg1 := make([]byte, 0, msg1Size)
	msg1 = append(msg1, iv...)
	msg1 = append(msg1, pqCt...)
	msg1 = append(msg1, sealRecord(c2sAEAD, zeroNonce, inner)...)
	if _, err := conn.Write(msg1); err != nil {
		return nil, fmt.Errorf("socks5s: send handshake: %w", err)
	}

	// Opening this is the proof that the peer holds the server's private key.
	resp, err := openRecord(conn, s2cAEAD, zeroNonce)
	if err != nil {
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			return nil, fmt.Errorf(
				"%w: the server closed before responding (wrong key, or the server's key was rotated?)", errAuth)
		}
		return nil, err
	}
	if len(resp) != msg2PayloadSize {
		return nil, fmt.Errorf("%w: unexpected response length %d", errAuth, len(resp))
	}
	pqSS2, err := pfsKey.Decapsulate(resp[:mlkemCiphertextLen])
	if err != nil {
		return nil, fmt.Errorf("%w: %v", errAuth, err)
	}
	sx, err := ecdh.X25519().NewPublicKey(resp[mlkemCiphertextLen:])
	if err != nil {
		return nil, fmt.Errorf("%w: %v", errAuth, err)
	}
	xSS, err := px.ECDH(sx)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", errAuth, err)
	}

	pfsSS := make([]byte, 0, sharedKeyLen*2)
	pfsSS = append(pfsSS, xSS...)
	pfsSS = append(pfsSS, pqSS2...)

	c2s, s2c, err := deriveMaster(nfsSS, pfsSS, iv)
	if err != nil {
		return nil, err
	}
	return newSecureConn(conn, c2s, s2c)
}

// deriveNFS splits the static layer secret into one key per direction, so the
// two directions can never reuse a nonce even though they share a secret.
//
// One expand produces both halves: HKDF is the second most expensive thing in
// the handshake after the public key operations, and each call rebuilds an HMAC
// state from scratch.
func deriveNFS(nfsSS, iv []byte) (c2s, s2c []byte, err error) {
	both, err := hkdfKey(nfsSS, iv, "qxproxy nfs v1", masterKeyLen)
	if err != nil {
		return nil, nil, err
	}
	return both[:32], both[32:], nil
}

// deriveMaster combines both layers.
//
//	ikm    = static secret || ephemeral X25519 secret || ephemeral ML-KEM secret
//	master = HKDF-SHA256(ikm, salt = iv, info = "qxproxy v1", 64)
//
// pfsSS is 64 bytes: the X25519 shared secret followed by the ML-KEM shared
// secret. It is destroyed with the connection, which is what makes the session
// key forward secret.
func deriveMaster(nfsSS, pfsSS, iv []byte) (c2s, s2c []byte, err error) {
	ikm := make([]byte, 0, sharedKeyLen*3)
	ikm = append(ikm, nfsSS...)
	ikm = append(ikm, pfsSS...)

	master, err := hkdfKey(ikm, iv, "qxproxy v1", masterKeyLen)
	if err != nil {
		return nil, nil, err
	}
	return master[:32], master[32:], nil
}

// hkdfKey expands secret into n bytes.
//
// The reference calls the Go 1.24 standard library's crypto/hkdf.Key, which
// this module cannot use because mihomo declares go 1.20. golang.org/x/crypto
// exposes the same RFC 5869 construction as a reader; the output is identical,
// which the package tests pin against the RFC 5869 vector.
func hkdfKey(secret, salt []byte, info string, n int) ([]byte, error) {
	r := hkdf.New(sha256.New, secret, salt, []byte(info))
	out := make([]byte, n)
	if _, err := io.ReadFull(r, out); err != nil {
		return nil, err
	}
	return out, nil
}

// gcm builds an AES-256-GCM AEAD.
//
// AES-GCM rather than ChaCha20-Poly1305 because the reference depends on the
// standard library alone, and matching it keeps the two interoperable.
func gcm(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}
