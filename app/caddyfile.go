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
	no_proxy | env_proxy
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
				app.UpstreamRaw = caddyconfig.JSONModuleObject(new(CaddyUpstream), "upstream", "caddy", nil)
			case "env_proxy":
				if app.ProxyRaw != nil {
					return nil, d.Err("only one proxy is allowed")
				}
				app.ProxyRaw = caddyconfig.JSONModuleObject(new(EnvProxy), "proxy", "env_proxy", nil)
			case "no_proxy":
				if app.ProxyRaw != nil {
					return nil, d.Err("only one proxy is allowed")
				}
				app.ProxyRaw = caddyconfig.JSONModuleObject(new(NoProxy), "proxy", "no_proxy", nil)
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
