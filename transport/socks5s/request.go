package socks5s

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"

	"github.com/metacubex/mihomo/transport/socks5"
)

// The tunnel request frame opens a session. It travels as the first encrypted
// record, so nothing in it is visible on the wire.
//
//	u8 version | ATYP | ADDR | u16 port
//
// There is no credential in the frame: the credential is the key string itself.
// Only a peer holding the server's public key can complete the handshake at
// all, and the server key never appears on the wire.
const protocolVersion = 1

// frameAddrSize bounds the wire form of an address: ATYP plus a 255 byte domain
// plus a two byte port, matching socks5.MaxAddrLen.
const frameAddrSize = socks5.MaxAddrLen

// EncodeRequest builds the request frame for a destination.
//
// The address uses the SOCKS5 encoding so no translation is needed at either
// end, but the frame is not a SOCKS5 request: it starts with the protocol
// version rather than the SOCKS version and carries no command byte.
func EncodeRequest(target socks5.Addr) ([]byte, error) {
	if len(target) == 0 {
		return nil, errors.New("socks5s: empty target address")
	}
	if len(target) > frameAddrSize {
		return nil, fmt.Errorf("socks5s: target address is %d bytes, want at most %d", len(target), frameAddrSize)
	}
	frame := make([]byte, 0, 1+len(target))
	frame = append(frame, protocolVersion)
	return append(frame, target...), nil
}

// AddrFromHostPort renders a destination as a SOCKS5 address.
//
// A literal IP is written as-is; a hostname stays a domain name so the server
// resolves it. Resolving here would pin the client's DNS answer onto a server
// that may resolve differently, and would leak the lookup to the client's
// resolver.
func AddrFromHostPort(host string, port uint16) (socks5.Addr, error) {
	if host == "" {
		return nil, errors.New("socks5s: empty target host")
	}
	if ip, err := netip.ParseAddr(host); err == nil {
		addr := socks5.AddrFromStdAddrPort(netip.AddrPortFrom(ip, port))
		if len(addr) == 0 {
			return nil, fmt.Errorf("socks5s: cannot encode address %s", host)
		}
		return addr, nil
	}
	if len(host) > 255 {
		return nil, fmt.Errorf("socks5s: target host is %d bytes, want at most 255", len(host))
	}
	addr := make([]byte, 0, 1+1+len(host)+2)
	addr = append(addr, socks5.AtypDomainName, byte(len(host)))
	addr = append(addr, host...)
	var p [2]byte
	binary.BigEndian.PutUint16(p[:], port)
	return append(addr, p[:]...), nil
}

// readRequest decodes a request frame. It is the server-side counterpart of
// encodeRequest and exists for tests and for tooling; the client never reads
// one.
func readRequest(r io.Reader) (socks5.Addr, uint8, error) {
	var head [2]byte
	if _, err := io.ReadFull(r, head[:]); err != nil {
		return nil, 0, err
	}
	version := head[0]
	if version != protocolVersion {
		return nil, version, fmt.Errorf("socks5s: unsupported protocol version %d", version)
	}
	atyp := head[1]

	var body []byte
	switch atyp {
	case socks5.AtypIPv4:
		body = make([]byte, net.IPv4len+2)
	case socks5.AtypIPv6:
		body = make([]byte, net.IPv6len+2)
	case socks5.AtypDomainName:
		var l [1]byte
		if _, err := io.ReadFull(r, l[:]); err != nil {
			return nil, version, err
		}
		if l[0] == 0 {
			return nil, version, errors.New("socks5s: empty domain name")
		}
		body = make([]byte, int(l[0])+2)
	default:
		return nil, version, fmt.Errorf("socks5s: unknown address type 0x%02x", atyp)
	}
	if _, err := io.ReadFull(r, body); err != nil {
		return nil, version, err
	}
	addr := make([]byte, 0, 2+len(body))
	addr = append(addr, atyp)
	return append(addr, body...), version, nil
}

// addrPortString renders a SOCKS5 address for logging.
func addrPortString(addr socks5.Addr) string {
	if len(addr) == 0 {
		return ""
	}
	return addr.String()
}
