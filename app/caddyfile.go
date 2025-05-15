package app

import (
	"encoding/json"
	"fmt"

	"github.com/caddyserver/caddy/v2/caddyconfig"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/imgk/caddy-trojan/pkgs/x"
)

func init() {
	httpcaddyfile.RegisterGlobalOption("trojan", parseCaddyfile)
}

/*
	trojan {
		caddy
		no_proxy | env_proxy | socks_proxy server user passwd | http_proxy server user passwd
		named_proxy proxy_name proxy_type server user password
		users pass1234 word5678
	}
*/
func parseCaddyfile(d *caddyfile.Dispenser, _ any) (any, error) {
	app := &App{
		UpstreamRaw:   nil,
		ProxyRaw:      nil,
		NamedProxyRaw: map[string]json.RawMessage{},
		Users:         []string{},
	}

	for d.Next() {
		for d.NextBlock(0) {
			subdirective := d.Val()
			switch subdirective {
			case "caddy":
				if app.UpstreamRaw != nil {
					return nil, d.Err("only one upstream is allowed")
				}
				app.UpstreamRaw = caddyconfig.JSONModuleObject(new(CaddyUpstream), "upstream", "caddy", nil)
			case "memory":
				if app.UpstreamRaw != nil {
					return nil, d.Err("only one upstream is allowed")
				}
				mod := new(MemoryUpstream)
				if args := d.RemainingArgs(); len(args) == 0 {
					app.UpstreamRaw = caddyconfig.JSONModuleObject(mod, "upstream", "memory", nil)
					var err error
					app.UpstreamRaw, err = x.RemoveNullKeysFromJSON(app.UpstreamRaw)
					if err != nil {
						return nil, fmt.Errorf("remove null key error: %w", err)
					}
				} else {
					if arg := args[0]; arg == "caddy" {
						mod.UpstreamRaw = caddyconfig.JSONModuleObject(new(CaddyUpstream), "upstream", "caddy", nil)
						app.UpstreamRaw = caddyconfig.JSONModuleObject(mod, "upstream", "memory", nil)
					} else {
						return nil, fmt.Errorf("unknown upstream module: %s", arg)
					}
				}
			case "no_proxy", "env_proxy", "socks_proxy", "http_proxy", "unix_proxy":
				if app.ProxyRaw != nil {
					return nil, d.Err("only one proxy is allowed")
				}
				parser, ok := GetProxyParser(subdirective)
				if !ok {
					return nil, d.Errf("unknown proxy type: %s", subdirective)
				}
				raw, err := parser(d.RemainingArgs())
				if err != nil {
					return nil, d.Err(err.Error())
				}
				app.ProxyRaw = raw
			case "users":
				args := d.RemainingArgs()
				if len(args) < 1 {
					return nil, d.ArgErr()
				}
				for _, v := range args {
					if len(v) == 0 {
						return nil, d.Err("empty user is not allowed")
					}
					app.Users = append(app.Users, v)
				}
			case "named_proxy":
				args := d.RemainingArgs()
				if len(args) < 2 {
					return nil, d.ArgErr()
				}
				name, typ := args[0], args[1]
				parser, ok := GetProxyParser(typ)
				if !ok {
					return nil, d.Errf("unsupported proxy type: %s", typ)
				}
				raw, err := parser(args[2:])
				if err != nil {
					return nil, d.Err(err.Error())
				}
				app.NamedProxyRaw[name] = raw
			default:
				parser, ok := GetProxyParser(subdirective)
				if ok {
					if app.ProxyRaw != nil {
						return nil, d.Err("only one proxy is allowed")
					}
					raw, err := parser(d.RemainingArgs())
					if err != nil {
						return nil, d.Err(err.Error())
					}
					app.ProxyRaw = raw
					continue
				}

				return nil, d.ArgErr()
			}
		}
	}

	if app.ProxyRaw == nil {
		app.ProxyRaw = caddyconfig.JSONModuleObject(new(NoProxy), "proxy", "none", nil)
	}

	if app.UpstreamRaw == nil {
		app.UpstreamRaw = caddyconfig.JSONModuleObject(new(MemoryUpstream), "upstream", "memory", nil)

		var err error
		app.UpstreamRaw, err = x.RemoveNullKeysFromJSON(app.UpstreamRaw)
		if err != nil {
			return nil, fmt.Errorf("remove null key error: %w", err)
		}
	}

	return httpcaddyfile.App{
		Name:  "trojan",
		Value: caddyconfig.JSON(app, nil),
	}, nil
}
