# Caddy-Trojan

## Build with xcaddy
```
$ xcaddy build --with github.com/imgk/caddy-trojan
```

##  Config (Caddyfile)
```
{
	order trojan before file_server
	servers :443 {
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
	tls your@email.com #optional, recommended
	trojan {
		connect_method
		websocket
	}
	file_server {
		root /var/www/html
	}
}
```
##  Config (JSON)
```
{
  "apps": {
    "http": {
      "servers": {
        "srv0": {
          "listen": [":443"],
          "listener_wrappers": [{
            "wrapper": "trojan"
          }],
          "routes": [{
            "handle": [{
              "handler": "trojan",
              "connect_method": true,
              "websocket": true
            },
            {
              "handler": "file_server",
              "root": "/var/www/html"
            }]
          }]
        }
      }
    },
    "trojan": {
      "upstream": {
        "upstream": "caddy"
      },
      "proxy": {
        "proxy": "no_proxy"
      },
      "users": ["pass1234","word5678"]
    },
    "tls": {
      "certificates": {
        "automate": ["example.com"]
      },
      "automation": {
        "policies": [{
          "issuers": [{
            "module": "acme",
            "email": "your@email.com" //optional,recommended
          },
          {
            "module": "zerossl",
            "email": "your@email.com" //optional,recommended
          }]
        }]
      }
    }
  }
}
```

## Manage Users

1. Add user.
```
curl -X POST -H "Content-Type: application/json" -d '{"password": "test1234"}' http://localhost:2019/trojan/users/add
```
