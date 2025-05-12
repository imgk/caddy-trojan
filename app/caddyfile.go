package app

import (
	"encoding/json"

	"github.com/caddyserver/caddy/v2/caddyconfig"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
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
		NamedProxy:    map[string]Proxy{},
	}

	for d.Next() {
		for d.NextBlock(0) {
			switch d.Val() {
			case "caddy":
				if app.UpstreamRaw != nil {
					return nil, d.Err("only one upstream is allowed")
				}
				app.UpstreamRaw = caddyconfig.JSONModuleObject(new(CaddyUpstream), "upstream", "caddy", nil)
			case "memory":
				if app.UpstreamRaw != nil {
					return nil, d.Err("only one upstream is allowed")
				}
				app.UpstreamRaw = caddyconfig.JSONModuleObject(new(MemoryUpstream), "upstream", "memory", nil)
			case "env_proxy":
				if app.ProxyRaw != nil {
					return nil, d.Err("only one proxy is allowed")
				}
				app.ProxyRaw = caddyconfig.JSONModuleObject(new(EnvProxy), "proxy", "env", nil)
			case "no_proxy":
				if app.ProxyRaw != nil {
					return nil, d.Err("only one proxy is allowed")
				}
				app.ProxyRaw = caddyconfig.JSONModuleObject(new(NoProxy), "proxy", "none", nil)
			case "socks_proxy":
				if app.ProxyRaw != nil {
					return nil, d.Err("only one proxy is allowed")
				}

				args := d.RemainingArgs()
				if len(args) < 1 {
					return nil, d.Err("server params is missing")
				} else if len(args) == 2 {
					return nil, d.Err("passwd params is missing")
				}

				socks := new(SocksProxy)
				socks.Server = args[0]
				if len(args) > 1 {
					socks.User = args[1]
					socks.Password = args[2]
				}
				app.ProxyRaw = caddyconfig.JSONModuleObject(socks, "proxy", "socks", nil)
			case "http_proxy":
				if app.ProxyRaw != nil {
					return nil, d.Err("only one proxy is allowed")
				}

				args := d.RemainingArgs()
				if len(args) < 1 {
					return nil, d.Err("server params is missing")
				} else if len(args) == 2 {
					return nil, d.Err("passwd params is missing")
				}

				http := new(HttpProxy)
				http.Server = args[0]
				if len(args) > 1 {
					http.User = args[1]
					http.Password = args[2]
				}
				app.ProxyRaw = caddyconfig.JSONModuleObject(http, "proxy", "http", nil)
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
				if len(args) != 3 || len(args) != 5 {
					return nil, d.ArgErr()
				}

				switch args[1] {
				case "socks":
					socks := new(SocksProxy)
					socks.Server = args[2]
					if len(args) > 3 {
						socks.User = args[3]
						socks.Password = args[4]
					}
					app.NamedProxyRaw[args[0]] = caddyconfig.JSONModuleObject(socks, "proxy", "socks", nil)
				case "http":
					http := new(HttpProxy)
					http.Server = args[2]
					if len(args) > 3 {
						http.User = args[3]
						http.Password = args[4]
					}
					app.NamedProxyRaw[args[0]] = caddyconfig.JSONModuleObject(http, "proxy", "socks", nil)
				default:
					return nil, d.ArgErr()
				}
			default:
				return nil, d.ArgErr()
			}
		}
	}

	if app.ProxyRaw == nil {
		app.ProxyRaw = caddyconfig.JSONModuleObject(new(NoProxy), "proxy", "none", nil)
	}

	if app.UpstreamRaw == nil {
		app.UpstreamRaw = caddyconfig.JSONModuleObject(new(MemoryUpstream), "upstream", "memory", nil)
	}

	return httpcaddyfile.App{
		Name:  "trojan",
		Value: caddyconfig.JSON(app, nil),
	}, nil
}
