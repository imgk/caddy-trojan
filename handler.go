package trojan

import (
	"errors"
	"fmt"
	"io"
	"net/http"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"

	"github.com/gorilla/websocket"
	"go.uber.org/zap"
)

func init() {
	caddy.RegisterModule(Handler{})
}

// Handler implements an HTTP handler that ...
type Handler struct {
	// Users is ...
	Users []string `json:"users"`
	// Upstream is ...
	Upstream string `json:"upstream,omitempty"`

	// upstream is ...
	upstream *Upstream

	// logger is ...
	logger *zap.Logger

	// upgrader is ...
	upgrader websocket.Upgrader
}

// CaddyModule returns the Caddy module information.
func (Handler) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.trojan",
		New: func() caddy.Module { return new(Handler) },
	}
}

// Provision implements caddy.Provisioner.
func (m *Handler) Provision(ctx caddy.Context) (err error) {
	m.logger = ctx.Logger(m)
	if len(m.Users) == 0 && m.Upstream == "" {
		m.upstream = upstream
		return
	}
	if !upstream.Ready() {
		m.upstream, err = upstream.Setup(m.Users, m.Upstream)
		return
	}
	return errors.New("only one upstream is allowed")
}

// Cleanup implements caddy.CleanerUpper
func (m *Handler) Cleanup() error {
	if len(m.Users) == 0 && m.Upstream == "" {
		return nil
	}
	m.upstream.Reset()
	return nil
}

// ServeHTTP implements caddyhttp.MiddlewareHandler.
func (m *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	// trojan over http2/http3
	// use CONNECT method, put trojan header as Proxy-Authorization
	if r.Method == http.MethodConnect {
		// fmt.Printf("Basic %v", base64.Encode(hex.Encode(sha256.Sum224([]byte("Test1234")))))
		const AuthLen = 82

		// handle trojan over http2/http3
		if r.ProtoMajor == 1 {
			return next.ServeHTTP(w, r)
		}
		auth := r.Header.Get("Proxy-Authorization")
		if len(auth) != AuthLen {
			return next.ServeHTTP(w, r)
		}
		if ok := m.upstream.Validate(auth); !ok {
			return next.ServeHTTP(w, r)
		}
		m.logger.Info(fmt.Sprintf("handle trojan http2/http3 from %v", r.RemoteAddr))

		nr, nw, err := Handle(r.Body, &FlushWriter{w: w, f: w.(http.Flusher)})
		if err != nil {
			m.logger.Error(fmt.Sprintf("handle http2/http3 error: %v", err))
		}
		m.upstream.Consume(r.Header.Get("Proxy-Authorization"), true, nr, nw)
		return nil
	}

	// handle websocket
	if websocket.IsWebSocketUpgrade(r) {
		conn, err := m.upgrader.Upgrade(w, r, nil)
		if err != nil {
			return err
		}

		c := &wsConn{Conn: conn, r: (*eofReader)(nil)}
		defer c.Close()

		b := [HeaderLen + 2]byte{}
		if _, err := io.ReadFull(c, b[:]); err != nil {
			m.logger.Error(fmt.Sprintf("read trojan header error: %v", err))
			return nil
		}
		if ok := m.upstream.Validate(ByteSliceToString(b[:HeaderLen])); !ok {
			return nil
		}
		m.logger.Info(fmt.Sprintf("handle trojan websocket.Conn from %v", r.RemoteAddr))

		nr, nw, err := Handle(io.Reader(c), io.Writer(c))
		if err != nil {
			m.logger.Error(fmt.Sprintf("handle websocket error: %v", err))
		}
		m.upstream.Consume(r.Header.Get("Proxy-Authorization"), true, nr, nw)
		return nil
	}
	return next.ServeHTTP(w, r)
}

// Interface guards
var (
	_ caddy.Provisioner           = (*Handler)(nil)
	_ caddyhttp.MiddlewareHandler = (*Handler)(nil)
	_ caddy.CleanerUpper          = (*Handler)(nil)
)

// FlushWriter is ...
type FlushWriter struct {
	w io.Writer
	f http.Flusher
}

// Writer is ...
func (c *FlushWriter) Write(b []byte) (int, error) {
	n, err := c.w.Write(b)
	c.f.Flush()
	return n, err
}
