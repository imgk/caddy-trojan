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
                "": {
                    "listener_wrappers": [{
                        "wrapper": "trojan"
                    }],
                    "routes": [
                        {
                            "handle": [
                                {
                                    "handler": "trojan",
                                    "connect_method": false,
                                    "websocket": false
                                }
                            ]
                        }
                    ]
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
            "users": ["pass1234", "word5678"],
        }
    }
}
```
##  Config (Caddyfile)

```
{
	servers {
		listener_wrappers {
			trojan
		}
	}
	trojan {
		caddy
		no_proxy
		users pass1234 word5678
	}
}

:443, example.com {
	tls email@example.com
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
