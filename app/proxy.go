package app

import (
	"errors"
	"io"
	"net"

	"golang.org/x/net/proxy"

	"github.com/caddyserver/caddy/v2"

	"github.com/imgk/caddy-trojan/pkgs/trojan"
)

func init() {
	caddy.RegisterModule(NoProxy{})
	caddy.RegisterModule(EnvProxy{})
}

// Proxy is ...
type Proxy interface {
	// Handle is ...
	Handle(r io.Reader, w io.Writer) (int64, int64, error)
	// Closer is ...
	io.Closer
}

// NoProxy is ...
type NoProxy struct{}

// CaddyModule is ...
func (NoProxy) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "trojan.proxy.no_proxy",
		New: func() caddy.Module { return new(NoProxy) },
	}
}

// Handle is ...
func (*NoProxy) Handle(r io.Reader, w io.Writer) (int64, int64, error) {
	return trojan.Handle(r, w)
}

// Close is ...
func (*NoProxy) Close() error {
	return nil
}

// EnvProxy is ...
type EnvProxy struct {
	proxy.Dialer `json:"-,omitempty"`
}

// CaddyModule is ...
func (EnvProxy) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "trojan.proxy.env_proxy",
		New: func() caddy.Module { return new(EnvProxy) },
	}
}

// Provision is ...
func (p *EnvProxy) Provision(ctx caddy.Context) error {
	p.Dialer = proxy.FromEnvironment()
	return nil
}

// Handle is ...
func (p *EnvProxy) Handle(r io.Reader, w io.Writer) (int64, int64, error) {
	return trojan.HandleWithDialer(r, w, p)
}

// Close is ...
func (*EnvProxy) Close() error {
	return nil
}

// ListenPacket is ...
func (*EnvProxy) ListenPacket(network, addr string) (net.PacketConn, error) {
	return nil, errors.New("proxy from environment does not support UDP")
}

var (
	_ Proxy             = (*NoProxy)(nil)
	_ caddy.Provisioner = (*EnvProxy)(nil)
	_ Proxy             = (*EnvProxy)(nil)
)
