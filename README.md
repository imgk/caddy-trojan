# Caddy-Trojan

## Build with xcaddy
```
$ xcaddy build \
    --with github.com/imgk/caddy-trojan/handler \
    --with github.com/imgk/caddy-trojan/listerner
```

## Config
```
{
    "apps": {
        "http": {
            "servers": {
                "": {
                    "listener_wrappers": [{
                        "wrapper": "trojan",
                        "trojan": {
                            "users": ["user-1", "user-2"],
                            "redis": {
                                "addr": "",
                                "password": "",
                                "db": 0
                            }
                        }
                    }],
                    "routes": [
                        {
                            "handle": [
                                {
                                    "handler": "trojan",
                                    "trojan": {
                                        "users": ["user-1", "user-2"],
                                        "redis": {
                                            "addr": "",
                                            "password": "",
                                            "db": 0
                                        }
                                    }
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
