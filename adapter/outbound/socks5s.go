package outbound

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"time"

	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/transport/socks5s"
)

// Socks5s tunnels TCP through a server speaking the socks5s protocol: a SOCKS5
// proxy carried over a post-quantum encrypted stream.
//
// Only the client role exists here, because a proxy client never terminates the
// tunnel. UDP is not implemented by the protocol at all, so it stays off
// regardless of the configuration: the reference answers a UDP ASSOCIATE with
// "command not supported".
type Socks5s struct {
	*Base
	option     *Socks5sOption
	encryption string
}

type Socks5sOption struct {
	BasicOption
	Name       string `proxy:"name"`
	Server     string `proxy:"server"`
	Port       int    `proxy:"port"`
	Encryption string `proxy:"encryption,omitempty"`
	UDP        bool   `proxy:"udp,omitempty"`
}

// handshakeTimeout bounds the dial plus the one round trip the handshake takes.
const socks5sDialTimeout = 10 * time.Second

func (s *Socks5s) DialContext(ctx context.Context, metadata *C.Metadata) (_ C.Conn, err error) {
	if s.encryption == "" {
		return nil, fmt.Errorf("socks5s %s: encryption is empty", s.Name())
	}

	// The credential is validated on every dial rather than only at startup,
	// so a malformed key fails the connection with a precise message instead
	// of making the whole configuration unloadable.
	addr, err := socks5s.AddrFromHostPort(metadata.Host, uint16(metadata.DstPort))
	if err != nil {
		return nil, fmt.Errorf("socks5s %s: %w", s.Name(), err)
	}

	dialCtx := ctx
	if _, hasDeadline := ctx.Deadline(); !hasDeadline {
		var cancel context.CancelFunc
		dialCtx, cancel = context.WithTimeout(ctx, socks5sDialTimeout)
		defer cancel()
	}

	c, err := s.dialer.DialContext(dialCtx, "tcp", s.addr)
	if err != nil {
		return nil, fmt.Errorf("%s connect error: %w", s.addr, err)
	}
	defer func(c net.Conn) {
		safeConnClose(c, err)
	}(c)

	tunnel, err := socks5s.ClientHandshake(c, s.encryption)
	if err != nil {
		return nil, fmt.Errorf("socks5s %s: %w", s.Name(), err)
	}

	frame, err := socks5s.EncodeRequest(addr)
	if err != nil {
		return nil, fmt.Errorf("socks5s %s: %w", s.Name(), err)
	}
	// The request rides the session key, one round trip after the greeting, so
	// it must be written before any application byte can be relayed.
	if _, err := tunnel.Write(frame); err != nil {
		return nil, fmt.Errorf("socks5s %s: write request: %w", s.Name(), err)
	}

	// The deadband the dial context imposed belongs to the handshake only.
	setStreamDeadline(tunnel)

	return NewConn(tunnel, s), nil
}

// ListenPacketContext reports that UDP is unavailable.
//
// Returning C.ErrNotSupport rather than a bare error is what lets the rule
// engine fall back or reject the packet knowingly, instead of reporting a
// transport fault.
func (s *Socks5s) ListenPacketContext(ctx context.Context, metadata *C.Metadata) (C.PacketConn, error) {
	return nil, C.ErrNotSupport
}

func (s *Socks5s) ProxyInfo() C.ProxyInfo {
	info := s.Base.ProxyInfo()
	info.DialerProxy = s.option.DialerProxy
	return info
}

func NewSocks5s(option Socks5sOption) (*Socks5s, error) {
	if option.Server == "" || option.Port <= 0 || option.Port > 0xffff {
		return nil, fmt.Errorf("socks5s %s requires a valid server and port", option.Name)
	}
	if option.Encryption == "" {
		return nil, fmt.Errorf("socks5s %s requires an encryption key", option.Name)
	}

	addr := net.JoinHostPort(option.Server, strconv.Itoa(option.Port))
	outbound := &Socks5s{
		Base: NewBase(BaseOption{
			Name:         option.Name,
			Addr:         addr,
			Type:         C.Socks5s,
			ProviderName: option.ProviderName,
			// The protocol is TCP only, so UDP stays off even when the
			// configuration asks for it.
			UDP:         false,
			TFO:         option.TFO,
			MPTCP:       option.MPTCP,
			Interface:   option.Interface,
			RoutingMark: option.RoutingMark,
			Prefer:      option.IPVersion,
		}),
		option:     &option,
		encryption: option.Encryption,
	}
	outbound.dialer = option.NewDialer(outbound.DialOptions())
	return outbound, nil
}

// setStreamDeadline clears a deadline this package set for the handshake, so
// the relay that follows is not cut short by it.
func setStreamDeadline(c net.Conn) {
	_ = c.SetDeadline(time.Time{})
}
