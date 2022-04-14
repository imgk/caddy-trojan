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
                    "allow_h2c": true,
                    "routes": [
                        {
                            "handle": [
                                {
                                    "handler": "trojan",
                                    "users": ["test1234", "word1234"],
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
		protocol {
			allow_h2c
			experimental_http3
		}
	}
}
:443, example.com {
	tls email@example.com
	route {
		trojan {
			user test1234
			user word1234 user1234
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
