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

	"github.com/imgk/caddy-trojan/trojan"
	"github.com/imgk/caddy-trojan/utils"
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
	Connect   bool     `json:"connect_method,omitempty"`
	Verbose   bool     `json:"verbose,omitempty"`

	// upstream is ...
	upstream Upstream
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
	m.upstream = NewUpstream(ctx.Storage())
	for _, v := range m.Users {
		m.upstream.Add(v)
	}
	return nil
}

// ServeHTTP implements caddyhttp.MiddlewareHandler.
func (m *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	// trojan over http2/http3
	// use CONNECT method, put trojan header as Proxy-Authorization
	if m.Connect && r.Method == http.MethodConnect {
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
		if m.Verbose {
			m.logger.Info(fmt.Sprintf("handle trojan http%d from %v", r.ProtoMajor, r.RemoteAddr))
		}

		nr, nw, err := trojan.Handle(r.Body, &FlushWriter{w: w, f: w.(http.Flusher)})
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

		b := [trojan.HeaderLen + 2]byte{}
		if _, err := io.ReadFull(c, b[:]); err != nil {
			m.logger.Error(fmt.Sprintf("read trojan header error: %v", err))
			return nil
		}
		if ok := m.upstream.Validate(utils.ByteSliceToString(b[:trojan.HeaderLen])); !ok {
			return nil
		}
		if m.Verbose {
			m.logger.Info(fmt.Sprintf("handle trojan websocket.Conn from %v", r.RemoteAddr))
		}

		nr, nw, err := trojan.Handle(io.Reader(c), io.Writer(c))
		if err != nil {
			m.logger.Error(fmt.Sprintf("handle websocket error: %v", err))
		}
		m.upstream.Consume(utils.ByteSliceToString(b[:trojan.HeaderLen]), nr, nw)
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
			if h.WebSocket {
				return d.Err("only one websocket is not allowed")
			}
			h.WebSocket = true
		case "connect_method":
			if h.Connect {
				return d.Err("only one connect_method is not allowed")
			}
			h.Connect = true
		case "verbose":
			if h.Verbose {
				return d.Err("only one connect_method is not allowed")
			}
			h.Verbose = true
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

// Write is ...
func (c *FlushWriter) Write(b []byte) (int, error) {
	n, err := c.w.Write(b)
	c.f.Flush()
	return n, err
}
