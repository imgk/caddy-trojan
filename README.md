# Caddy-Trojan

## Build with xcaddy
```
$ xcaddy build --with github.com/imgk/caddy-trojan
```

## Config
```jsonc
{
    "apps": {
        "http": {
            "servers": {
                "": {
                    "listener_wrappers": [{
                        "wrapper": "trojan"
                    }],
                    // set true to enable http2
                    "allow_h2c": true,
                    "routes": [
                        {
                            "handle": [
                                {
                                    "handler": "trojan"
                                }
                            ]
                        }
                    ]
                }
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
