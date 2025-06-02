package app

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"

	"github.com/caddyserver/caddy/v2"
	"github.com/imgk/caddy-trojan/pkgs/trojan"

	"github.com/shadowsocks/go-shadowsocks2/core"
	"github.com/shadowsocks/go-shadowsocks2/socks"
)

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
	return nil
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

func (p *ShadowsocksProxy) ListenPacket(network, addr string) (net.PacketConn, error) {
	pc, err := p.proxy.ListenPacket(network, addr)
	if err != nil {
		return nil, err
	}

	return p.cipher.PacketConn(pc), nil
}

var (
	_ Proxy             = (*ShadowsocksProxy)(nil)
	_ trojan.Dialer     = (*ShadowsocksProxy)(nil)
	_ caddy.Provisioner = (*ShadowsocksProxy)(nil)
)
