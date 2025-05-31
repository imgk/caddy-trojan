package app

import (
	"fmt"
	"net"
	"net/netip"

	"github.com/caddyserver/caddy/v2"
	"github.com/imgk/caddy-trojan/pkgs/trojan"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

type WireGuardProxy struct {
	Address    string `json:"address"`
	DNSServer  string `json:"dns_server"`
	PrivateKey string `json:"private_key"`
	PublicKey  string `json:"public_key"`
	AllowedIP  string `json:"allowed_ip,omitempty"`
	Endpoint   string `json:"endpoint"`

	dev  *device.Device
	tnet *netstack.Net
}

func (WireGuardProxy) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "trojan.proxy.wireguard",
		New: func() caddy.Module { return new(WireGuardProxy) },
	}
}

func (p *WireGuardProxy) Provision(ctx caddy.Context) error {
	addr, err := netip.ParseAddr(p.Address)
	if err != nil {
		return fmt.Errorf("parse address error: %w", err)
	}

	naddr, err := netip.ParseAddr(p.DNSServer)
	if err != nil {
		return fmt.Errorf("parse dns server error: %w", err)
	}

	tun, tnet, err := netstack.CreateNetTUN([]netip.Addr{addr}, []netip.Addr{naddr}, 1420)
	if err != nil {
		return fmt.Errorf("create netstack error: %w", err)
	}
	p.tnet = tnet

	if p.AllowedIP == "" {
		p.AllowedIP = "0.0.0.0/0"
	}

	conf := "private_key=" + p.PrivateKey + "\n" +
		"public_key=" + p.PublicKey + "\n" +
		"allowed_ip=" + p.AllowedIP + "\n" +
		"endpoint=" + p.Endpoint + "\n"

	dev := device.NewDevice(tun, conn.NewDefaultBind(), device.NewLogger(device.LogLevelVerbose, ""))
	if err := dev.IpcSet(conf); err != nil {
		return fmt.Errorf("set config error: %w", err)
	}
	p.dev = dev

	if err := dev.Up(); err != nil {
		return fmt.Errorf("device up error: %w", err)
	}

	return nil
}

func (p *WireGuardProxy) Close() error {
	p.dev.Close()
	return nil
}

func (p *WireGuardProxy) Dial(network, addr string) (net.Conn, error) {
	return p.tnet.Dial(network, addr)
}

func (p *WireGuardProxy) ListenPacket(network, addr string) (net.PacketConn, error) {
	naddr, err := netip.ParseAddrPort(addr)
	if err != nil {
		return nil, err
	}
	return p.tnet.ListenUDPAddrPort(naddr)
}

var (
	_ Proxy             = (*WireGuardProxy)(nil)
	_ trojan.Dialer     = (*WireGuardProxy)(nil)
	_ caddy.Provisioner = (*WireGuardProxy)(nil)
)
