package app

import (
	"bufio"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"

	"golang.org/x/net/proxy"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig"

	"github.com/imgk/caddy-trojan/pkgs/trojan"
)

func init() {
	caddy.RegisterModule(NoProxy{})
	caddy.RegisterModule(noProxy{})
	caddy.RegisterModule(EnvProxy{})
	caddy.RegisterModule(envProxy{})
	caddy.RegisterModule(SocksProxy{})
	caddy.RegisterModule(HttpProxy{})

	RegisterProxyParser("no", func(args []string) (json.RawMessage, error) {
		return caddyconfig.JSONModuleObject(new(NoProxy), "proxy", "none", nil), nil
	})

	RegisterProxyParser("none", func(args []string) (json.RawMessage, error) {
		return caddyconfig.JSONModuleObject(new(NoProxy), "proxy", "none", nil), nil
	})

	RegisterProxyParser("env", func(args []string) (json.RawMessage, error) {
		return caddyconfig.JSONModuleObject(new(EnvProxy), "proxy", "env", nil), nil
	})

	RegisterProxyParser("socks", func(args []string) (json.RawMessage, error) {
		if len(args) < 1 {
			return nil, fmt.Errorf("server params is missing")
		} else if len(args) == 2 {
			return nil, fmt.Errorf("passwd params is missing")
		}

		socks := new(SocksProxy)
		socks.Server = args[0]
		if len(args) > 1 {
			socks.User = args[1]
			socks.Password = args[2]
		}
		return caddyconfig.JSONModuleObject(socks, "proxy", "socks", nil), nil
	})

	RegisterProxyParser("http", func(args []string) (json.RawMessage, error) {
		if len(args) < 1 {
			return nil, fmt.Errorf("server params is missing")
		} else if len(args) == 2 {
			return nil, fmt.Errorf("passwd params is missing")
		}

		http := new(HttpProxy)
		http.Server = args[0]
		if len(args) > 1 {
			http.User = args[1]
			http.Password = args[2]
		}
		return caddyconfig.JSONModuleObject(http, "proxy", "http", nil), nil
	})
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
		ID:  "trojan.proxy.none",
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

type noProxy struct {
	NoProxy
}

func (noProxy) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "trojan.proxy.no_proxy",
		New: func() caddy.Module { return new(noProxy) },
	}
}

// EnvProxy is ...
type EnvProxy struct {
	proxy.Dialer `json:"-,omitempty"`
}

// CaddyModule is ...
func (EnvProxy) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "trojan.proxy.env",
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

type envProxy struct {
	EnvProxy
}

func (envProxy) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "trojan.proxy.env_proxy",
		New: func() caddy.Module { return new(envProxy) },
	}
}

// SocksProxy is a caddy module and supports socks5 proxy server.
// All tcp connections will be sent to proxy server.
type SocksProxy struct {
	Server   string `json:"server"`
	User     string `json:"user,omitempty"`
	Password string `json:"password,omitempty"`

	dialer proxy.Dialer
}

func (SocksProxy) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "trojan.proxy.socks",
		New: func() caddy.Module { return new(SocksProxy) },
	}
}

func (p *SocksProxy) Provision(ctx caddy.Context) error {
	if p.User == "" && p.Password != "" {
		return errors.New("empty user")
	}
	if p.User != "" && p.Password == "" {
		return errors.New("empty password")
	}

	var err error
	if p.User == "" && p.Password == "" {
		p.dialer, err = proxy.SOCKS5("socks5", p.Server, nil, nil)
	} else {
		p.dialer, err = proxy.SOCKS5("socks5", p.Server, &proxy.Auth{User: p.User, Password: p.Password}, nil)
	}
	if err != nil {
		return err
	}

	return nil
}

func (p *SocksProxy) Handle(r io.Reader, w io.Writer) (int64, int64, error) {
	return trojan.HandleWithDialer(r, w, p)
}

func (p *SocksProxy) Close() error {
	return nil
}

func (p *SocksProxy) Dial(network, addr string) (net.Conn, error) {
	return p.dialer.Dial(network, addr)
}

func (p *SocksProxy) ListenPacket(network, addr string) (net.PacketConn, error) {
	return nil, errors.New("socks5 UDP Associate not supported")
}

// HttpProxy is a caddy module and supports socks5 proxy server.
// All tcp connections will be sent to proxy server.
type HttpProxy struct {
	Server   string `json:"server"`
	User     string `json:"user,omitempty"`
	Password string `json:"password,omitempty"`

	basicAuth string
	tcpURL    string
}

func (HttpProxy) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "trojan.proxy.http",
		New: func() caddy.Module { return new(HttpProxy) },
	}
}

func (p *HttpProxy) Provision(ctx caddy.Context) error {
	if p.User == "" && p.Password != "" {
		return errors.New("empty user")
	}
	if p.User != "" && p.Password == "" {
		return errors.New("empty password")
	}

	if p.User != "" && p.Password != "" {
		p.basicAuth = "basic " + base64.StdEncoding.EncodeToString([]byte(p.User+":"+p.Password))
	}
	p.tcpURL = fmt.Sprintf("http://%s", p.Server)

	return nil
}

func (p *HttpProxy) Handle(r io.Reader, w io.Writer) (int64, int64, error) {
	return trojan.HandleWithDialer(r, w, p)
}

func (p *HttpProxy) Close() error {
	return nil
}

func (p *HttpProxy) Dial(network, addr string) (net.Conn, error) {
	conn, err := net.Dial("tcp", p.Server)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest(http.MethodConnect, p.tcpURL, nil)
	if err != nil {
		return conn, fmt.Errorf("request error: %w", err)
	}
	req.URL.Opaque = addr
	if p.basicAuth != "" {
		req.Header.Add("Proxy-Authorization", p.basicAuth)
	}

	err = req.WriteProxy(conn)
	if err != nil {
		return conn, fmt.Errorf("write request error: %w", err)
	}

	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		return conn, fmt.Errorf("read response error: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return conn, fmt.Errorf("server status code error: %v", resp.StatusCode)
	}
	return conn, nil
}

func (p *HttpProxy) ListenPacket(network, addr string) (net.PacketConn, error) {
	return nil, errors.New("does not support UDP for http proxy")
}

var (
	_ Proxy             = (*NoProxy)(nil)
	_ caddy.Provisioner = (*EnvProxy)(nil)
	_ Proxy             = (*EnvProxy)(nil)
	_ trojan.Dialer     = (*EnvProxy)(nil)
	_ caddy.Provisioner = (*SocksProxy)(nil)
	_ Proxy             = (*SocksProxy)(nil)
	_ trojan.Dialer     = (*SocksProxy)(nil)
	_ caddy.Provisioner = (*HttpProxy)(nil)
	_ Proxy             = (*HttpProxy)(nil)
	_ trojan.Dialer     = (*HttpProxy)(nil)
)
