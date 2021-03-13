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
                        "wrapper": "trojan",
                        "users": ["user-1", "user-2"] 
                    }],
                    // set true to enable http2
                    "allow_h2c": true,
                    "routes": [
                        {
                            "handle": [
                                {
                                    "handler": "trojan",
                                    "users", ["user-1", "user-2"]
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
