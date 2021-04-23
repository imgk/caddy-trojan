package trojan

import (
	"bytes"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"os"

	"github.com/caddyserver/caddy/v2"

	"go.uber.org/zap"
)

func init() {
	caddy.RegisterModule(ListenerWrapper{})
}

// ListenerWrapper implements an TLS wrapper that it accept connections
// from clients and check the connection with pre-defined password
// and aead cipher defined by go-shadowsocks2, and return a normal page if
// failed.
type ListenerWrapper struct {
	// Users is ...
	Users []string `json:"users"`
	// Upstream is ...
	Upstream string `json:"upstream,omitempty"`

	// upstream is ...
	upstream *Upstream

	// logger is ...
	logger *zap.Logger
}

// CaddyModule returns the Caddy module information.
func (ListenerWrapper) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "caddy.listeners.trojan",
		New: func() caddy.Module { return new(ListenerWrapper) },
	}
}

// Provision implements caddy.Provisioner.
func (m *ListenerWrapper) Provision(ctx caddy.Context) (err error) {
	m.logger = ctx.Logger(m)
	if upstream.Ready() {
		m.upstream, err = upstream.Setup(m.Users, m.Upstream)
		return
	}
	return errors.New("only one upstream is allowed")
}

// WrapListener implements caddy.ListenWrapper
func (m *ListenerWrapper) WrapListener(l net.Listener) net.Listener {
	ln := NewListener(l, m.upstream, m.logger)
	go ln.loop()
	return ln
}

// Interface guards
var (
	_ caddy.Provisioner     = (*ListenerWrapper)(nil)
	_ caddy.ListenerWrapper = (*ListenerWrapper)(nil)
)

// Listener is ...
type Listener struct {
	// Listener is ...
	net.Listener

	// upstream is ...
	upstream *Upstream

	// logging
	logger *zap.Logger

	// return *rawConn
	conns chan *rawConn

	// close channel
	closed chan struct{}
}

// NewListener is ...
func NewListener(ln net.Listener, up *Upstream, logger *zap.Logger) *Listener {
	l := &Listener{
		Listener: ln,
		upstream: up,
		logger:   logger,
		conns:    make(chan *rawConn, 8),
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
				l.logger.Error(fmt.Sprintf("accept net.Conn error: %v", err))
			}
			continue
		}

		go func(c net.Conn, lg *zap.Logger, up *Upstream) {
			b := make([]byte, HeaderLen+2)
			if _, err := io.ReadFull(c, b); err != nil {
				lg.Error(fmt.Sprintf("read prefix error: %v", err))
				c.Close()
				return
			}

			// check the net.Conn
			if ok := up.Validate(ByteSliceToString(b[:HeaderLen])); !ok {
				select {
				case <-l.closed:
					c.Close()
				default:
					l.conns <- &rawConn{Conn: c, r: bytes.NewReader(b)}
				}
				return
			}
			defer c.Close()
			lg.Info(fmt.Sprintf("handle trojan net.Conn from %v", c.RemoteAddr()))

			nr, nw, err := Handle(c, c)
			if err != nil {
				lg.Error(fmt.Sprintf("handle net.Conn error: %v", err))
			}
			up.Consume(ByteSliceToString(b[:HeaderLen]), false, nr, nw)
		}(conn, l.logger, l.upstream)
	}
}

// rawConn is ...
type rawConn struct {
	net.Conn
	r *bytes.Reader
}

// Read is ...
func (c *rawConn) Read(b []byte) (int, error) {
	if c.r == nil {
		return c.Conn.Read(b)
	}
	n, err := c.r.Read(b)
	if errors.Is(err, io.EOF) {
		c.r = nil
		return n, nil
	}
	return n, err
}

// CloseWrite is ...
func (c *rawConn) CloseWrite() error {
	if cc, ok := c.Conn.(*tls.Conn); ok {
		return cc.CloseWrite()
	}
	if cc, ok := c.Conn.(*net.TCPConn); ok {
		return cc.CloseWrite()
	}
	type CloseWriter interface {
		CloseWrite() error
	}
	if closer, ok := c.Conn.(CloseWriter); ok {
		return closer.CloseWrite()
	}
	return errors.New("not supported")
}
