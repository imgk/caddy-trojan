package trojan

import (
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"

	"github.com/gorilla/websocket"
	"go.uber.org/zap"
)

func init() {
	caddy.RegisterModule(Handler{})
	httpcaddyfile.RegisterHandlerDirective("trojan", func(h httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
		m := &Handler{}
		err := m.UnmarshalCaddyfile(h.Dispenser)
		return m, err
	})
}

// Handler implements an HTTP handler that ...
type Handler struct {
	Users     []string `json:"users,omitempty"`
	WebSocket bool     `json:"websocket,omitempty"`

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
func (m *Handler) Provision(ctx caddy.Context) error {
	m.logger = ctx.Logger(m)
	m.upstream = upstream
	for _, v := range m.Users {
		m.upstream.Add(v)
	}
	return nil
}

// ServeHTTP implements caddyhttp.MiddlewareHandler.
func (m *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	// trojan over http2/http3
	// use CONNECT method, put trojan header as Proxy-Authorization
	if r.Method == http.MethodConnect {
		// base64.StdEncoding.Encode(hex.Encode(sha256.Sum224([]byte("Test1234"))))
		const AuthLen = 76

		// handle trojan over http2/http3
		if r.ProtoMajor == 1 {
			return next.ServeHTTP(w, r)
		}
		auth := strings.TrimPrefix(r.Header.Get("Proxy-Authorization"), "Basic ")
		if len(auth) != AuthLen {
			return next.ServeHTTP(w, r)
		}
		if ok := m.upstream.Validate(auth); !ok {
			return next.ServeHTTP(w, r)
		}
		m.logger.Info(fmt.Sprintf("handle trojan http%d from %v", r.ProtoMajor, r.RemoteAddr))

		nr, nw, err := Handle(r.Body, &FlushWriter{w: w, f: w.(http.Flusher)})
		if err != nil {
			m.logger.Error(fmt.Sprintf("handle http%d error: %v", r.ProtoMajor, err))
		}
		m.upstream.Consume(auth, nr, nw)
		return nil
	}

	// handle websocket
	if m.WebSocket && websocket.IsWebSocketUpgrade(r) {
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
		m.upstream.Consume(ByteSliceToString(b[:HeaderLen]), nr, nw)
		return nil
	}
	return next.ServeHTTP(w, r)
}

// UnmarshalCaddyfile unmarshals Caddyfile tokens into h.
func (h *Handler) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	if !d.Next() {
		return d.ArgErr()
	}
	args := d.RemainingArgs()
	if len(args) > 0 {
		return d.ArgErr()
	}
	for nesting := d.Nesting(); d.NextBlock(nesting); {
		subdirective := d.Val()
		args := d.RemainingArgs()
		switch subdirective {
		case "user":
			if len(args) < 1 {
				return d.ArgErr()
			}
			for _, v := range args {
				if len(v) == 0 {
					return d.Err("empty user is not allowed")
				}
				h.Users = append(h.Users, v)
			}
		case "websocket":
			h.WebSocket = true
		}
	}
	return nil
}

// Interface guards
var (
	_ caddy.Provisioner           = (*Handler)(nil)
	_ caddyhttp.MiddlewareHandler = (*Handler)(nil)
	_ caddyfile.Unmarshaler       = (*Handler)(nil)
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
