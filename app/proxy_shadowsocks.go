package app

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig"
	"github.com/imgk/caddy-trojan/pkgs/trojan"
	"github.com/imgk/caddy-trojan/pkgs/x"

	"github.com/shadowsocks/go-shadowsocks2/core"
	"github.com/shadowsocks/go-shadowsocks2/socks"
)

func init() {
	caddy.RegisterModule(ShadowsocksProxy{})

	fn := ProxyParser(nil)

	fn = func(args []string) (json.RawMessage, error) {
		if len(args) < 3 {
			return nil, fmt.Errorf("not enough shadowsocks config")
		}
		proxy := new(ShadowsocksProxy)
		proxy.Server, proxy.Password, proxy.Method = args[0], args[1], args[2]
		return x.RemoveNullKeysFromJSON(caddyconfig.JSONModuleObject(proxy, "proxy", "shadowsocks", nil))
	}
	RegisterProxyParser("shadowsocks", fn)
	RegisterProxyParser("shadowsocks_proxy", fn)
}

type ShadowsocksProxy struct {
	ProxyRaw json.RawMessage `json:"pre_proxy" caddy:"namespace=trojan.proxy inline_key=proxy"`

	Server   string `json:"server"`
	Password string `json:"password"`
	Method   string `json:"method"`

	proxy  Proxy
	cipher core.Cipher
}

func (ShadowsocksProxy) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "trojan.proxy.shadowsocks",
		New: func() caddy.Module { return new(ShadowsocksProxy) },
	}
}

func (p *ShadowsocksProxy) Provision(ctx caddy.Context) error {
	if p.ProxyRaw != nil {
		mod, err := ctx.LoadModule(p, "ProxyRaw")
		if err != nil {
			return nil
		}
		p.proxy = mod.(Proxy)
		return nil
	} else {
		p.proxy = &NoProxy{}
	}

	var err error
	p.cipher, err = core.PickCipher(p.Method, nil, p.Password)
	if err != nil {
		return fmt.Errorf("pick cipher error: %w", err)
	}

	return nil
}

func (p *ShadowsocksProxy) Close() error {
	return p.proxy.Close()
}

func (p *ShadowsocksProxy) Dial(network, addr string) (net.Conn, error) {
	switch network {
	case "tcp", "tcp4", "tcp6":
	default:
		return nil, &net.OpError{
			Op:  "dial",
			Err: errors.New("network error"),
		}
	}

	c, err := p.proxy.Dial("tcp", p.Server)
	if err != nil {
		c.Close()
		return nil, err
	}
	conn := p.cipher.StreamConn(c)

	tgt := socks.ParseAddr(addr)
	if tgt == nil {
		conn.Close()
		return nil, fmt.Errorf("parse address: %v error", addr)
	}

	if _, err := conn.Write(tgt); err != nil {
		conn.Close()
		return nil, err
	}

	return conn, nil
}

type ssPacketConn struct {
	net.PacketConn

	addr net.Addr
}

func (c *ssPacketConn) WriteTo(buf []byte, addr net.Addr) (int, error) {
	srcAddr := socks.ParseAddr(addr.String())
	buf = append(srcAddr, buf...)

	n, err := c.PacketConn.WriteTo(buf, c.addr)
	return n - len(srcAddr), err
}

func (c *ssPacketConn) ReadFrom(b []byte) (int, net.Addr, error) {
	n, _, err := c.PacketConn.ReadFrom(b)
	if err != nil {
		return 0, nil, err
	}

	tgt := socks.SplitAddr(b[:n])
	if tgt == nil {
		return 0, nil, fmt.Errorf("split address error: %w", err)
	}

	tgtUDP, err := net.ResolveUDPAddr("udp", tgt.String())
	if err != nil {
		return 0, nil, fmt.Errorf("resolve address error: %w", err)
	}

	copy(b, b[len(tgt):n])

	return n - len(tgt), tgtUDP, nil
}

func (p *ShadowsocksProxy) ListenPacket(network, addr string) (net.PacketConn, error) {
	pc, err := p.proxy.ListenPacket(network, addr)
	if err != nil {
		return nil, err
	}

	tgt, err := net.ResolveUDPAddr("udp", p.Server)
	if err != nil {
		return nil, fmt.Errorf("resolve address error: %w", err)
	}

	return &ssPacketConn{p.cipher.PacketConn(pc), tgt}, nil
}

var (
	_ Proxy             = (*ShadowsocksProxy)(nil)
	_ trojan.Dialer     = (*ShadowsocksProxy)(nil)
	_ caddy.Provisioner = (*ShadowsocksProxy)(nil)
)
