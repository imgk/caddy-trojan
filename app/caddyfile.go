package app

import (
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
		users pass1234 word5678
	}
*/
func parseCaddyfile(d *caddyfile.Dispenser, _ interface{}) (interface{}, error) {
	app := &App{
		UpstreamRaw: nil,
		ProxyRaw:    nil,
		Users:       []string{},
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
			}

		}
	}

	return httpcaddyfile.App{
		Name:  "trojan",
		Value: caddyconfig.JSON(app, nil),
	}, nil
}
