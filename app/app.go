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

const CaddyAppID = "trojan"

type App struct {
	UpstreamRaw   json.RawMessage            `json:"upstream" caddy:"namespace=trojan.upstream inline_key=upstream"`
	ProxyRaw      json.RawMessage            `json:"proxy" caddy:"namespace=trojan.proxy inline_key=proxy"`
	NamedProxyRaw map[string]json.RawMessage `json:"named_proxy,omitempty" caddy:"namespace=trojan.proxy inline_key=proxy"`
	Users         []string                   `json:"users,omitempty"`

	upstream   Upstream
	proxy      Proxy
	namedProxy map[string]Proxy

	lg *zap.Logger
}

func (App) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  CaddyAppID,
		New: func() caddy.Module { return new(App) },
	}
}

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
	app.upstream = mod.(Upstream)

	mod, err = ctx.LoadModule(app, "ProxyRaw")
	if err != nil {
		return err
	}
	app.proxy = mod.(Proxy)

	app.namedProxy = make(map[string]Proxy)
	if app.NamedProxyRaw != nil {
		vals, err := ctx.LoadModule(app, "NamedProxyRaw")
		if err != nil {
			return fmt.Errorf("loading trojan.proxy modules: %w", err)
		}
		for fieldName, modIface := range vals.(map[string]any) {
			app.namedProxy[fieldName] = modIface.(Proxy)
		}
	}

	for _, v := range app.Users {
		app.upstream.Add(v)
	}

	app.lg = ctx.Logger(app)

	return nil
}

func (app *App) Start() error {
	return nil
}

func (app *App) Stop() error {
	return app.proxy.Close()
}

func (app *App) GetUpstream() Upstream {
	return app.upstream
}

func (app *App) GetProxy() Proxy {
	return app.proxy
}

func (app *App) GetProxyByName(name string) (Proxy, bool) {
	proxy, ok := app.namedProxy[name]
	return proxy, ok
}

var (
	_ caddy.App         = (*App)(nil)
	_ caddy.Provisioner = (*App)(nil)
)
