package handler

import (
	"errors"
	"net"
	"net/http"
	"sync"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"

	"github.com/gorilla/websocket"
	"github.com/shadowsocks/go-shadowsocks2/core"
	"go.uber.org/zap"

	"github.com/imgk/caddy-trojan"
)

func init() {
	caddy.RegisterModule(Handler{})
}

// Handler implements an HTTP handler that ...
type Handler struct {
	Users []struct {
		Path     string `json:"path"`
		Method   string `json:"method"`
		Password string `json:"password"`
	} `json:"users,omitempty"`

	logger   *zap.Logger
	ciphers  map[string]core.Cipher
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
	m.ciphers = make(map[string]core.Cipher)
	for _, user := range m.Users {
		cipher, er := core.PickCipher(user.Method, []byte{}, user.Password)
		if er != nil {
			err = er
			return err
		}
		m.ciphers[user.Path] = cipher
	}
	m.upgrader = websocket.Upgrader{
		WriteBufferPool: &sync.Pool{
			New: newBuffer,
		},
	}
	return
}

// ServeHTTP implements caddyhttp.MiddlewareHandler.
func (m *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	if websocket.IsWebSocketUpgrade(r) {
		if cipher, ok := m.ciphers[r.URL.Path]; ok {
			stream, err := m.upgrader.Upgrade(w, r, nil)
			if err != nil {
				return err
			}
			return m.ServeProxy(cipher.StreamConn(trojan.NewWebSocketConn(stream)))
		}
		return next.ServeHTTP(w, r)
	}
	return next.ServeHTTP(w, r)
}

// Interface guards
var (
	_ caddy.Provisioner           = (*Handler)(nil)
	_ caddyhttp.MiddlewareHandler = (*Handler)(nil)
)

func newBuffer() interface{} {
	return make([]byte, 4*1024)
}

func (m *Handler) ServeProxy(conn net.Conn) error {
	usr, err := trojan.CheckConn(conn)
	if err != nil {
		defer conn.Close()
		if errors.Is(err, trojan.ErrNotTrojan) {
			return nil
		}
		m.logger.Error("handle websocket conn", zap.Error(err))
		return nil
	}

	usr.SetLogger(m.logger)
	if err := trojan.Handle(conn, usr); err != nil {
		m.logger.Error(usr.Name, zap.Error(err))
	}
	return nil
}
