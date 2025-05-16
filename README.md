# Caddy-Trojan -- A Caddy Module for Trojan Proxy

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
		# memory

		no_proxy
		# env_proxy
		# socks_proxy server user passwd
		# socks_proxy server
		# http_proxy server user passwd
		# http_proxy server
		# named_proxy proxy_name proxy_type args...

		users pass1234 word5678
	}
}
:443, example.com {
	tls your@email.com #optional,recommended
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
            "wrapper": "trojan",
            "proxy_name": "proxy_2"
          }],
          "routes": [{
            "handle": [{
              "handler": "trojan",
              "connect_method": true,
              "websocket": true,
              "proxy_name": "proxy_3"
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
      "named_proxy": {
        "proxy_1": {
          "proxy": "none"
        },
        "proxy_2": {
          "proxy": "socks",
          "server": "127.0.0.1:1080"
        },
        "proxy_3": {
          "proxy": "http",
          "server": "127.0.0.1:8080"
        }
      },
      "proxy": { //optional
        "proxy": "none"
      },
      "upstream": { //optional
        "upstream": "caddy"
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
            "module": "acme",
            "ca": "https://acme.zerossl.com/v2/DV90",
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

## Docker

```
git clone https://github.com/imgk/caddy-trojan
cd caddy-trojan/Dockerfiles
docker build -t caddy-trojan .
docker run --env MYPASSWD=MY_PASSWORD --env MYDOMAIN=MY_DOMAIN.COM -itd --name caddy-trojan --restart always -p 80:80 -p 443:443 caddy-trojan
```
