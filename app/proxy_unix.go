package app

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig"
	"github.com/imgk/caddy-trojan/pkgs/trojan"
)

func init() {
	caddy.RegisterModule(UnixProxy{})

	fn := ProxyParser(nil)

	fn = func(args []string) (json.RawMessage, error) {
		if len(args) == 0 {
			return nil, fmt.Errorf("empty path is not allowed")
		}
		uds := new(UnixProxy)
		uds.Path = args[0]
		return caddyconfig.JSONModuleObject(uds, "proxy", "unix", nil), nil
	}
	RegisterProxyParser("unix", fn)
	RegisterProxyParser("unix_proxy", fn)
}

// UnixProxy is ...
type UnixProxy struct {
	Path string `json:"path"`
}

// CaddyModule is ...
func (UnixProxy) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "trojan.proxy.unix",
		New: func() caddy.Module { return new(UnixProxy) },
	}
}

func (u *UnixProxy) Provision(ctx caddy.Context) error {
	if u.Path == "" {
		return errors.New("empty path")
	}
	return nil
}

// Handle is ...
func (p *UnixProxy) Handle(r io.Reader, w io.Writer) (int64, int64, error) {
	return trojan.HandleWithDialer(r, w, p)
}

// Close is ...
func (*UnixProxy) Close() error {
	return nil
}

func (u *UnixProxy) Dial(network, addr string) (net.Conn, error) {
	if u.Path == "" {
		return nil, errors.New("path is empty")
	}
	conn, err := net.Dial("unix", u.Path)
	if err != nil {
		return nil, err
	}
	err = writeTrojanUnixHandshake(conn, network, addr)
	if err != nil {
		return nil, err
	}
	return conn, nil
}

// ListenPacket is ...
func (*UnixProxy) ListenPacket(network, addr string) (net.PacketConn, error) {
	return nil, errors.New("unix proxy currently does not support UDP.")
}

// writeTrojanUnixHandshake writes the initial handshake header to a UNIX socket connection.
//
// Protocol format:
//
//	+------------------+--------+--------------+------------+-------------+-------------+--------+
//	| Magic[12]        | Ver[1] | NetType[1]   | AddrType[1]| AddrLen[1]* | Addr[N]     | Port[2]|
//	+------------------+--------+--------------+------------+-------------+-------------+--------+
//	| "caddy-trojan"   | 0x01   | 0x01=TCP     | 0x01=IPv4  | domain only | IP/domain   | BE u16 |
//	|                  |        | 0x02=UDP     | 0x02=IPv6  |             |             |        |
//	|                  |        |              | 0x03=Domain|             |             |        |
//	+------------------+--------+--------------+------------+-------------+-------------+--------+
//
// * AddrLen only exists when AddrType = 0x03 (domain)
func writeTrojanUnixHandshake(conn net.Conn, network, addr string) error {
	var buf bytes.Buffer

	// Magic identifier: "caddy-trojan" (12 bytes)
	magic := "caddy-trojan"
	if len(magic) != 12 {
		return errors.New("magic string must be 12 bytes")
	}
	buf.WriteString(magic)

	// Protocol version
	buf.WriteByte(0x01)

	// Network type
	var netType byte
	switch network {
	case "tcp", "tcp4", "tcp6":
		netType = 0x01
	case "udp", "udp4", "udp6":
		netType = 0x02
	default:
		return fmt.Errorf("unsupported network type: %s", network)
	}
	buf.WriteByte(netType)

	// Parse host and port
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("invalid addr: %w", err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return fmt.Errorf("invalid port: %w", err)
	}

	ip := net.ParseIP(host)
	if ip4 := ip.To4(); ip4 != nil {
		// IPv4
		buf.WriteByte(0x01)
		buf.Write(ip4)
	} else if ip16 := ip.To16(); ip16 != nil {
		// IPv6
		buf.WriteByte(0x02)
		buf.Write(ip16)
	} else {
		// Domain
		if len(host) > 255 {
			return errors.New("domain name too long")
		}
		buf.WriteByte(0x03)
		buf.WriteByte(byte(len(host)))
		buf.WriteString(host)
	}

	// Port (2 bytes big-endian)
	var portBytes [2]byte
	binary.BigEndian.PutUint16(portBytes[:], uint16(port))
	buf.Write(portBytes[:])

	// Send the handshake
	_, err = conn.Write(buf.Bytes())
	return err
}

var (
	_ Proxy             = (*UnixProxy)(nil)
	_ trojan.Dialer     = (*UnixProxy)(nil)
	_ caddy.Provisioner = (*UnixProxy)(nil)
)
