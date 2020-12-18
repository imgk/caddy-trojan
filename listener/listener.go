package listener

import (
	"crypto/tls"
	"errors"
	"net"
	"sync"

	"github.com/caddyserver/caddy/v2"

	"go.uber.org/zap"

	"github.com/imgk/caddy-trojan"
)

func init() {
	caddy.RegisterModule(Wrapper{})
}

// Wrapper implements an TLS wrapper that it accept connections
// from clients and check the connection with pre-defined password
// and aead cipher defined by go-shadowsocks2, and return a normal page if
// failed.
type Wrapper struct {
	App    trojan.App `json:"trojan"`
	logger *zap.Logger
}

// CaddyModule returns the Caddy module information.
func (Wrapper) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "caddy.listeners.trojan",
		New: func() caddy.Module { return new(Wrapper) },
	}
}

// Provision implements caddy.Provisioner.
func (m *Wrapper) Provision(ctx caddy.Context) (err error) {
	m.logger = ctx.Logger(m)
	err = m.App.Provision(m.logger)
	return
}

// WrapListener implements caddy.ListenWrapper
func (m *Wrapper) WrapListener(l net.Listener) net.Listener {
	ln := newListener(l, &m.App, m.logger)
	go ln.handleConn()
	return ln
}

// Interface guards
var (
	_ caddy.Provisioner     = (*Wrapper)(nil)
	_ caddy.ListenerWrapper = (*Wrapper)(nil)
)

var ErrListenerClosed = errors.New("listener already closed")

type Conn struct {
	conn net.Conn
	err  error
}

type listener struct {
	sync.Mutex
	net.Listener
	*trojan.App
	logger *zap.Logger
	closed bool
	conns  chan Conn
}

func newListener(ln net.Listener, app *trojan.App, logger *zap.Logger) *listener {
	return &listener{
		Mutex:    sync.Mutex{},
		Listener: ln,
		App:      app,
		logger:   logger,
		closed:   false,
		conns:    make(chan Conn, 10),
	}
}

func (l *listener) Accept() (net.Conn, error) {
	for {
		in, ok := <-l.conns
		if !ok {
			break
		}
		if _, ok := in.conn.(*net.TCPConn); ok {
			return in.conn, in.err
		}
		if in.err == nil {
			go l.Handle(in.conn)
			continue
		}
		if errors.Is(in.err, trojan.ErrNotTrojan) {
			return in.conn, nil
		}
		return in.conn, in.err
	}
	return nil, ErrListenerClosed
}

func (l *listener) Close() error {
	l.Mutex.Lock()
	defer l.Mutex.Unlock()
	if l.closed {
		return nil
	}
	l.closed = true
	close(l.conns)
	return l.Listener.Close()
}

func (l *listener) handleConn() {
	for {
		conn, err := l.Listener.Accept()
		l.Mutex.Lock()
		if l.closed {
			l.Mutex.Unlock()
			break
		}
		l.conns <- Conn{conn: conn, err: err}
		l.Mutex.Unlock()
	}
}

func (l *listener) Handle(conn net.Conn) (err error) {
	if c, ok := conn.(*tls.Conn); ok {
		if err := c.Handshake(); err != nil {
			l.logger.Error("tls handle shake", zap.Error(err))
			conn.Close()
			return nil
		}
	}

	conn = trojan.NewWrappedConn(conn)
	usr, err := l.App.CheckConn(conn)
	if err != nil {
		if !errors.Is(err, trojan.ErrNotTrojan) {
			l.logger.Error("handle wrapped conn", zap.Error(err))
			conn.Close()
			return
		}

		l.Mutex.Lock()
		defer l.Mutex.Unlock()
		if l.closed {
			return
		}
		l.conns <- Conn{conn: conn, err: trojan.ErrNotTrojan}
		return
	}

	usr.SetLogger(l.logger)
	if err := trojan.Handle(conn, usr); err != nil {
		l.logger.Error(usr.Name, zap.Error(err))
	}
	return nil
}
