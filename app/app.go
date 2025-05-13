package app

import (
	"encoding/json"
	"fmt"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig"
	"github.com/imgk/caddy-trojan/pkgs/x"
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
	// NamedProxyRaw is ...
	NamedProxyRaw map[string]json.RawMessage `json:"named_proxy,omitempty" caddy:"namespace=trojan.proxy inline_key=proxy"`
	// Users is ...
	Users []string `json:"users,omitempty"`

	Upstream   `json:"-,omitempty"`
	Proxy      `json:"-,omitempty"`
	NamedProxy map[string]Proxy `json:"-,omitempty"`

	lg *zap.Logger
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
	if app.ProxyRaw == nil {
		app.ProxyRaw = caddyconfig.JSONModuleObject(new(NoProxy), "proxy", "none", nil)
	}

	if app.UpstreamRaw == nil {
		app.UpstreamRaw = caddyconfig.JSONModuleObject(new(MemoryUpstream), "upstream", "memory", nil)

		var err error
		app.UpstreamRaw, err = x.RemoveNullKeysFromJSON(app.UpstreamRaw)
		if err != nil {
			return fmt.Errorf("remove null key error: %w", err)
		}
	}

	mod, err := ctx.LoadModule(app, "UpstreamRaw")
	if err != nil {
		return err
	}
	app.Upstream = mod.(Upstream)

	mod, err = ctx.LoadModule(app, "ProxyRaw")
	if err != nil {
		return err
	}
	app.Proxy = mod.(Proxy)

	app.NamedProxy = make(map[string]Proxy)
	if app.NamedProxyRaw != nil {
		vals, err := ctx.LoadModule(app, "NamedProxyRaw")
		if err != nil {
			return fmt.Errorf("loading trojan.proxy modules: %w", err)
		}
		for fieldName, modIface := range vals.(map[string]any) {
			app.NamedProxy[fieldName] = modIface.(Proxy)
		}
	}

	for _, v := range app.Users {
		app.Upstream.Add(v)
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
	return app.Proxy.Close()
}

// Upstream is ...
func (app *App) GetUpstream() Upstream {
	return app
}

// Proxy is ...
func (app *App) GetProxy() Proxy {
	return app
}

func (app *App) GetProxyByName(name string) (Proxy, bool) {
	v, ok := app.NamedProxy[name]
	return v, ok
}

var (
	_ caddy.App         = (*App)(nil)
	_ caddy.Provisioner = (*App)(nil)
)
