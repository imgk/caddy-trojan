package listener

import (
	"errors"
	"fmt"
	"io"
	"net"
	"os"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"

	"go.uber.org/zap"

	"github.com/imgk/caddy-trojan/app"
	"github.com/imgk/caddy-trojan/pkgs/rawconn"
	"github.com/imgk/caddy-trojan/pkgs/trojan"
	"github.com/imgk/caddy-trojan/pkgs/x"
)

func init() {
	caddy.RegisterModule(ListenerWrapper{})
}

// ListenerWrapper implements an TLS wrapper that it accept connections
// from clients and check the connection with pre-defined password
// and aead cipher defined by go-shadowsocks2, and return a normal page if
// failed.
type ListenerWrapper struct {
	// Upstream is ...
	Upstream app.Upstream `json:"-,omitempty"`
	// Proxy is ...
	Proxy app.Proxy `json:"-,omitempty"`
	// Logger is ...
	Logger *zap.Logger `json:"-,omitempty"`
	// Verbose is ...
	Verbose bool `json:"verbose,omitempty"`
}

// CaddyModule returns the Caddy module information.
func (ListenerWrapper) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "caddy.listeners.trojan",
		New: func() caddy.Module { return new(ListenerWrapper) },
	}
}

// Provision implements caddy.Provisioner.
func (m *ListenerWrapper) Provision(ctx caddy.Context) error {
	m.Logger = ctx.Logger(m)
	ctx.App(app.CaddyAppID)
	if _, err := ctx.AppIfConfigured(app.CaddyAppID); err != nil {
		return fmt.Errorf("trojan configure error: %w", err)
	}
	mod, err := ctx.App(app.CaddyAppID)
	if err != nil {
		return err
	}
	app := mod.(*app.App)
	m.Upstream = app.GetUpstream()
	m.Proxy = app.GetProxy()
	return nil
}

// WrapListener implements caddy.ListenWrapper
func (m *ListenerWrapper) WrapListener(l net.Listener) net.Listener {
	ln := NewListener(l, m.Upstream, m.Proxy, m.Logger)
	ln.Verbose = m.Verbose
	go ln.loop()
	return ln
}

// UnmarshalCaddyfile unmarshals Caddyfile tokens into h.
func (*ListenerWrapper) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	return nil
}

// Interface guards
var (
	_ caddy.Provisioner     = (*ListenerWrapper)(nil)
	_ caddy.ListenerWrapper = (*ListenerWrapper)(nil)
	_ caddyfile.Unmarshaler = (*ListenerWrapper)(nil)
)

// Listener is ...
type Listener struct {
	Verbose bool

	// Listener is ...
	net.Listener
	// Upstream is ...
	Upstream app.Upstream
	// Proxy is ...
	Proxy app.Proxy
	// Logger is ...
	Logger *zap.Logger

	// return *rawConn
	conns chan net.Conn
	// close channel
	closed chan struct{}
}

// NewListener is ...
func NewListener(ln net.Listener, up app.Upstream, px app.Proxy, logger *zap.Logger) *Listener {
	l := &Listener{
		Listener: ln,
		Upstream: up,
		Proxy:    px,
		Logger:   logger,
		conns:    make(chan net.Conn, 8),
		closed:   make(chan struct{}),
	}
	return l
}

// Accept is ...
func (l *Listener) Accept() (net.Conn, error) {
	select {
	case <-l.closed:
		return nil, os.ErrClosed
	case c := <-l.conns:
		return c, nil
	}
}

// Close is ...
func (l *Listener) Close() error {
	select {
	case <-l.closed:
		return nil
	default:
		close(l.closed)
	}
	return nil
}

// loop is ...
func (l *Listener) loop() {
	for {
		conn, err := l.Listener.Accept()
		if err != nil {
			select {
			case <-l.closed:
				return
			default:
				l.Logger.Error(fmt.Sprintf("accept net.Conn error: %v", err))
			}
			continue
		}

		go func(c net.Conn, lg *zap.Logger, up app.Upstream) {
			b := make([]byte, trojan.HeaderLen+2)
			for n := 0; n < trojan.HeaderLen+2; n += 1 {
				nr, err := c.Read(b[n : n+1])
				if err != nil {
					if errors.Is(err, io.EOF) {
						lg.Error(fmt.Sprintf("read prefix error: read tcp %v -> %v: read: %v", c.RemoteAddr(), c.LocalAddr(), err))
					} else {
						lg.Error(fmt.Sprintf("read prefix error, not io, rewind and let normal caddy deal with it: %v", err))
						l.conns <- rawconn.RewindConn(c, b[:n+1])
						return
					}
					c.Close()
					return
				}
				if nr == 0 {
					continue
				}
				// mimic nginx
				if b[n] == 0x0a && n < trojan.HeaderLen+1 {
					select {
					case <-l.closed:
						c.Close()
					default:
						l.conns <- rawconn.RewindConn(c, b[:n+1])
					}
					return
				}
			}

			// check the net.Conn
			if ok := up.Validate(x.ByteSliceToString(b[:trojan.HeaderLen])); !ok {
				select {
				case <-l.closed:
					c.Close()
				default:
					l.conns <- rawconn.RewindConn(c, b)
				}
				return
			}
			defer c.Close()
			if l.Verbose {
				lg.Info(fmt.Sprintf("handle trojan net.Conn from %v", c.RemoteAddr()))
			}

			nr, nw, err := l.Proxy.Handle(io.Reader(c), io.Writer(c))
			if err != nil {
				lg.Error(fmt.Sprintf("handle net.Conn error: %v", err))
			}
			up.Consume(x.ByteSliceToString(b[:trojan.HeaderLen]), nr, nw)
		}(conn, l.Logger, l.Upstream)
	}
}
