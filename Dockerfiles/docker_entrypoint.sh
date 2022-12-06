#!/bin/sh

if [[ "$MYPASSWD" == "123456" || "$MYPASSWD" == "MY_PASSWORD" ]]; then
    echo please reset your password && exit 1
fi

if [[ "$MYDOMAIN" == "1.1.1.1.nip.io" || "$MYDOMAIN" == "MY_DOMAIN.COM" ]]; then
    echo please reset your domain name && exit 1
fi

# config
cat <<EOF >/etc/caddy/Caddyfile
{
    order trojan before route
    servers :443 {
        listener_wrappers {
            trojan
        }
    }
    trojan {
        caddy
        no_proxy
        users $MYPASSWD
    }
}
:443, $MYDOMAIN {
    trojan {
        connect_method
        websocket
    }
    @host host $MYDOMAIN
    route @host {
        file_server {
            root /usr/share/caddy
        }
    }
}
EOF

# start
caddy run --config /etc/caddy/Caddyfile --adapter caddyfile