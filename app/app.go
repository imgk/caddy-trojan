package app

import (
	"encoding/json"

	"github.com/caddyserver/caddy/v2"
	"go.uber.org/zap"
)

func init() {
	caddy.RegisterModule(App{})
}

// CaddyAppID is ...
const CaddyAppID = "trojan"

// App is ...
type App struct {
	// UpstreamRaw is ...
	UpstreamRaw json.RawMessage `json:"upstream" caddy:"namespace=trojan.upstream inline_key=upstream"`
	// ProxyRaw is ...
	ProxyRaw json.RawMessage `json:"proxy" caddy:"namespace=trojan.proxy inline_key=proxy"`
	// Users is ...
	Users []string `json:"users,omitempty"`

	lg *zap.Logger
	up Upstream
	px Proxy
}

// CaddyModule is ...
func (App) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  CaddyAppID,
		New: func() caddy.Module { return new(App) },
	}
}

// Provision is ...
func (app *App) Provision(ctx caddy.Context) error {
	mod, err := ctx.LoadModule(app, "UpstreamRaw")
	if err != nil {
		return err
	}
	app.up = mod.(Upstream)

	mod, err = ctx.LoadModule(app, "ProxyRaw")
	if err != nil {
		return err
	}
	app.px = mod.(Proxy)

	for _, v := range app.Users {
		app.up.Add(v)
	}

	app.lg = ctx.Logger(app)

	return nil
}

// Start is ...
func (app *App) Start() error {
	return nil
}

// Stop is ...
func (app *App) Stop() error {
	return app.px.Close()
}

// Upstream is ...
func (app *App) Upstream() Upstream {
	return app.up
}

// Proxy is ...
func (app *App) Proxy() Proxy {
	return app.px
}

var (
	_ caddy.App         = (*App)(nil)
	_ caddy.Provisioner = (*App)(nil)
)
