# Caddy-Trojan

## Build with xcaddy
```
$ xcaddy build --with github.com/imgk/caddy-trojan
```

##  Config (JSON)
```jsonc
{
    "apps": {
        "http": {
            "servers": {
                "srv0": {
                    "listen": [":443"],
                    "listener_wrappers": [
                        {
                            "wrapper": "trojan"
                        }
		    ],
                    "routes": [
                        {
                            "handle": [
                                {
                                    "handler": "trojan",
                                    "connect_method": true,
                                    "websocket": true
                                }
                            ]
                        },
                        {
                            "handle": [
                                {
                                    "handler": "file_server",
                                    "root": "/var/www/html"
                                }
                            ]
                        }
                    ],
                    "protocols": ["h1","h2c","h2"]
                }
            }
        },
        "trojan":{
            "upstream": {
                "upstream": "caddy"
            },
            "proxy": {
                "proxy": "no_proxy"
            },
            "users": ["pass1234", "word5678"]
        }
    }
}
```
##  Config (Caddyfile)

```
{
	servers :443 {
		listener_wrappers {
			trojan
		}
		protocols h1 h2c h2
	}
	trojan {
		caddy
		no_proxy
		users pass1234 word5678
	}
}

:443, example.com {
	route {
		trojan {
			connect_method
			websocket
		}
		file_server {
			root /var/www/html
		}
	}
}
```

## Manage Users

1. Add user.
```
curl -X POST -H "Content-Type: application/json" -d '{"password": "test1234"}' http://localhost:2019/trojan/users/add
```
