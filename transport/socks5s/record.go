package socks5s

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"time"
)

// The record layer wraps an authenticated byte stream over a plain TCP
// connection.
//
// Every record carries five bytes of header that are, byte for byte, a TLS 1.3
// application-data record header. The header is passed to the AEAD as
// additional data, so its length field is authenticated: flipping one bit makes
// the record fail to open. The TLS shape costs nothing and keeps the stream
// from looking like a bespoke protocol.
const (
	recordHeaderSize = 5

	// maxPlaintext matches the TLS 1.3 record limit.
	maxPlaintext = 16384
	maxRecord    = maxPlaintext + recordTagLen

	// recordTagLen is the AES-GCM tag size.
	recordTagLen = 16

	// ivLen is the handshake's random salt.
	ivLen = 16
)

var (
	tlsRecordHeader = [3]byte{0x17, 0x03, 0x03}

	// zeroNonce is used for the two handshake records, each of which is sealed
	// under a key that is never reused.
	zeroNonce [12]byte

	// errRecord marks a malformed or unauthentic record.
	errRecord = errors.New("socks5s: malformed or unauthenticated record")
)

// aeadState is one direction's AES-256-GCM key and record counter.
//
// The counter occupies the last eight bytes of the 96-bit nonce, leaving the
// first four zero. That is 2^64 records of up to 16 KiB each, far beyond any
// physical transfer, and reaching it is fatal rather than a silent nonce reuse.
type aeadState struct {
	aead  cipher.AEAD
	nonce [12]byte
}

func newAEADState(key []byte) (*aeadState, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return &aeadState{aead: gcm}, nil
}

func (a *aeadState) next() ([]byte, error) {
	ctr := binary.BigEndian.Uint64(a.nonce[4:])
	if ctr == math.MaxUint64 {
		return nil, errors.New("socks5s: nonce space exhausted")
	}
	binary.BigEndian.PutUint64(a.nonce[4:], ctr+1)
	return a.nonce[:], nil
}

// recordHeader writes the five byte TLS shaped header for a ciphertext of l
// bytes.
func recordHeader(dst []byte, l int) {
	dst[0], dst[1], dst[2] = tlsRecordHeader[0], tlsRecordHeader[1], tlsRecordHeader[2]
	dst[3], dst[4] = byte(l>>8), byte(l)
}

// sealRecord frames and seals one handshake record.
//
// Callers pass zeroNonce, and each handshake key is used for exactly one
// record, so the pair is single use. Handshake keys are derived per direction
// precisely so that this cannot happen by accident.
func sealRecord(aead cipher.AEAD, nonce [12]byte, plaintext []byte) []byte {
	out := make([]byte, recordHeaderSize, recordHeaderSize+len(plaintext)+recordTagLen)
	recordHeader(out, len(plaintext)+recordTagLen)
	return aead.Seal(out, nonce[:], plaintext, out[:recordHeaderSize])
}

// openRecord reads and opens one handshake record. Like sealRecord it runs once
// per key, at nonce zero.
func openRecord(r io.Reader, aead cipher.AEAD, nonce [12]byte) ([]byte, error) {
	var hdr [recordHeaderSize]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, err
	}
	if hdr[0] != tlsRecordHeader[0] || hdr[1] != tlsRecordHeader[1] || hdr[2] != tlsRecordHeader[2] {
		return nil, fmt.Errorf("%w: bad record header %x", errRecord, hdr)
	}
	l := int(hdr[3])<<8 | int(hdr[4])
	if l < recordTagLen+1 || l > maxRecord {
		return nil, fmt.Errorf("%w: bad record length %d", errRecord, l)
	}
	buf := make([]byte, l)
	if _, err := io.ReadFull(r, buf); err != nil {
		return nil, err
	}
	pt, err := aead.Open(buf[:0], nonce[:], buf, hdr[:])
	if err != nil {
		return nil, fmt.Errorf("%w: %v", errRecord, err)
	}
	return pt, nil
}

// SecureConn is an authenticated, encrypted byte stream over a net.Conn.
//
// Read decrypts in place into the caller's buffer whenever it is large enough,
// so the steady-state data path is kernel -> caller's buffer -> in place
// decryption -> target, with no staging copy.
type SecureConn struct {
	net.Conn
	send *aeadState
	recv *aeadState

	// Buffers used only when the caller's read buffer is smaller than one
	// record.
	ctBuf   []byte
	ptBuf   []byte
	pending []byte
}

func newSecureConn(c net.Conn, keyC2S, keyS2C []byte) (*SecureConn, error) {
	send, err := newAEADState(keyC2S)
	if err != nil {
		return nil, err
	}
	recv, err := newAEADState(keyS2C)
	if err != nil {
		return nil, err
	}
	return &SecureConn{Conn: c, send: send, recv: recv}, nil
}

func (c *SecureConn) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	if len(c.pending) > 0 {
		n := copy(p, c.pending)
		c.pending = c.pending[n:]
		return n, nil
	}

	var hdr [recordHeaderSize]byte
	if _, err := io.ReadFull(c.Conn, hdr[:]); err != nil {
		return 0, err
	}
	if hdr[0] != tlsRecordHeader[0] || hdr[1] != tlsRecordHeader[1] || hdr[2] != tlsRecordHeader[2] {
		return 0, errRecord
	}
	l := int(hdr[3])<<8 | int(hdr[4])
	if l < recordTagLen+1 || l > maxRecord {
		return 0, errRecord
	}
	ptLen := l - recordTagLen

	nonce, err := c.recv.next()
	if err != nil {
		return 0, err
	}

	// Fast path: decrypt straight into the caller's buffer. GCM accepts
	// dst == ciphertext[:0], so the ciphertext is overwritten in place.
	if cap(p) >= l {
		ct := p[:l]
		if _, err := io.ReadFull(c.Conn, ct); err != nil {
			return 0, err
		}
		pt, err := c.recv.aead.Open(p[:0], nonce, ct, hdr[:])
		if err != nil {
			return 0, errRecord
		}
		return len(pt), nil
	}

	// Slow path: the caller's buffer cannot hold a whole record.
	if cap(c.ctBuf) < l {
		c.ctBuf = make([]byte, l)
	}
	ct := c.ctBuf[:l]
	if _, err := io.ReadFull(c.Conn, ct); err != nil {
		return 0, err
	}
	// Sized to the record rather than to the maximum: the only slow path
	// reader is the request frame, and reserving 16 KiB per connection for it
	// would be 16 KiB of retained memory per session.
	if cap(c.ptBuf) < ptLen {
		c.ptBuf = make([]byte, ptLen)
	}
	pt, err := c.recv.aead.Open(c.ptBuf[:0], nonce, ct, hdr[:])
	if err != nil {
		return 0, errRecord
	}
	n := copy(p, pt)
	c.pending = pt[n:]
	return n, nil
}

// sealTo appends one framed, sealed record for p to dst, advancing the send
// counter. Keeping it separate lets the handshake build a whole flight in one
// buffer instead of issuing one write per record.
func (c *SecureConn) sealTo(dst, p []byte) ([]byte, error) {
	nonce, err := c.send.next()
	if err != nil {
		return dst, err
	}
	// The header is copied in before sealing and also passed as additional
	// data, so its length field is authenticated and the ciphertext can be
	// appended straight after it.
	var hdr [recordHeaderSize]byte
	recordHeader(hdr[:], len(p)+recordTagLen)
	dst = append(dst, hdr[:]...)
	return c.send.aead.Seal(dst, nonce, p, hdr[:]), nil
}

func (c *SecureConn) Write(p []byte) (int, error) {
	total := 0
	// One record's worth of scratch is reused across the whole write, so a
	// large payload does not allocate per record.
	out := make([]byte, 0, recordHeaderSize+maxPlaintext+recordTagLen)
	for len(p) > 0 {
		chunk := p
		if len(chunk) > maxPlaintext {
			chunk = chunk[:maxPlaintext]
		}
		rec, err := c.sealTo(out[:0], chunk)
		if err != nil {
			return total, err
		}
		if _, werr := c.Conn.Write(rec); werr != nil {
			return total, werr
		}
		total += len(chunk)
		p = p[len(chunk):]
	}
	return total, nil
}

// CloseWrite half-closes the sending direction. Because the record layer is a
// byte stream, the peer sees a clean EOF once every preceding record is read.
func (c *SecureConn) CloseWrite() error {
	if hc, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return hc.CloseWrite()
	}
	return c.Conn.Close()
}

// CloseRead shuts down the receiving direction.
func (c *SecureConn) CloseRead() error {
	if hc, ok := c.Conn.(interface{ CloseRead() error }); ok {
		return hc.CloseRead()
	}
	return c.Conn.Close()
}

// setDeadline bounds a phase, or clears the bound when d is zero.
func setDeadline(c net.Conn, d time.Duration) {
	if d > 0 {
		_ = c.SetDeadline(time.Now().Add(d))
	} else {
		_ = c.SetDeadline(time.Time{})
	}
}
