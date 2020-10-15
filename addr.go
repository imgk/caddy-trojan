package trojan

import (
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
)

const MaxAddrLen = 1 + 1 + 255 + 2

const (
	AddrTypeIPv4   = 1
	AddrTypeDomain = 3
	AddrTypeIPv6   = 4
)

type errAddrType byte

func (e errAddrType) Error() string {
	return fmt.Sprintf("address type %v error", byte(e))
}

type Addr []byte

func (addr Addr) Network() string {
	return "socks"
}

func (addr Addr) String() string {
	switch addr[0] {
	case AddrTypeIPv4:
		host := net.IP(addr[1 : 1+net.IPv4len]).String()
		port := strconv.Itoa(int(addr[1+net.IPv4len])<<8 | int(addr[1+net.IPv4len+1]))
		return net.JoinHostPort(host, port)
	case AddrTypeDomain:
		host := string(addr[2 : 2+addr[1]])
		port := strconv.Itoa(int(addr[2+addr[1]])<<8 | int(addr[2+addr[1]+1]))
		return net.JoinHostPort(host, port)
	case AddrTypeIPv6:
		host := net.IP(addr[1 : 1+net.IPv6len]).String()
		port := strconv.Itoa(int(addr[1+net.IPv6len])<<8 | int(addr[1+net.IPv6len+1]))
		return net.JoinHostPort(host, port)
	default:
		return ""
	}
}

func ResolveTCPAddr(addr Addr) (*net.TCPAddr, error) {
	switch addr[0] {
	case AddrTypeIPv4:
		host := net.IP(addr[1 : 1+net.IPv4len])
		port := int(addr[1+net.IPv4len])<<8 | int(addr[1+net.IPv4len+1])
		return &net.TCPAddr{IP: host, Port: port}, nil
	case AddrTypeDomain:
		return net.ResolveTCPAddr("tcp", addr.String())
	case AddrTypeIPv6:
		host := net.IP(addr[1 : 1+net.IPv6len])
		port := int(addr[1+net.IPv6len])<<8 | int(addr[1+net.IPv6len+1])
		return &net.TCPAddr{IP: host, Port: port}, nil
	default:
		return nil, errAddrType(addr[0])
	}
}

func ResolveUDPAddr(addr Addr) (*net.UDPAddr, error) {
	switch addr[0] {
	case AddrTypeIPv4:
		host := net.IP(addr[1 : 1+net.IPv4len])
		port := int(addr[1+net.IPv4len])<<8 | int(addr[1+net.IPv4len+1])
		return &net.UDPAddr{IP: host, Port: port}, nil
	case AddrTypeDomain:
		return net.ResolveUDPAddr("udp", addr.String())
	case AddrTypeIPv6:
		host := net.IP(addr[1 : 1+net.IPv6len])
		port := int(addr[1+net.IPv6len])<<8 | int(addr[1+net.IPv6len+1])
		return &net.UDPAddr{IP: host, Port: port}, nil
	default:
		return nil, errAddrType(addr[0])
	}
}

var ErrAddr = errors.New("tcp and udp only")

func ResolveAddrBuffer(addr net.Addr, b []byte) (Addr, error) {
	if naddr, ok := addr.(*net.TCPAddr); ok {
		if ip := naddr.IP.To4(); ip != nil {
			b[0] = AddrTypeIPv4
			copy(b[1:1+net.IPv4len], ip)
			b[1+net.IPv4len] = byte(naddr.Port >> 8)
			b[1+net.IPv4len+1] = byte(naddr.Port)

			return b[:1+net.IPv4len+2], nil
		} else {
			ip = naddr.IP.To16()

			b[0] = AddrTypeIPv6
			copy(b[1:1+net.IPv6len], ip)
			b[1+net.IPv6len] = byte(naddr.Port >> 8)
			b[1+net.IPv6len+1] = byte(naddr.Port)

			return b[:1+net.IPv6len+2], nil
		}
	}

	if naddr, ok := addr.(*net.UDPAddr); ok {
		if ip := naddr.IP.To4(); ip != nil {
			b[0] = AddrTypeIPv4
			copy(b[1:1+net.IPv4len], ip)
			b[1+net.IPv4len] = byte(naddr.Port >> 8)
			b[1+net.IPv4len+1] = byte(naddr.Port)

			return b[:1+net.IPv4len+2], nil
		} else {
			ip = naddr.IP.To16()

			b[0] = AddrTypeIPv6
			copy(b[1:1+net.IPv6len], ip)
			b[1+net.IPv6len] = byte(naddr.Port >> 8)
			b[1+net.IPv6len+1] = byte(naddr.Port)

			return b[:1+net.IPv6len+2], nil
		}
	}

	return b, ErrAddr
}

func ReadAddrBuffer(conn net.Conn, addr []byte) (Addr, error) {
	_, err := io.ReadFull(conn, addr[:2])
	if err != nil {
		return nil, err
	}

	switch addr[0] {
	case AddrTypeIPv4:
		n := 1 + net.IPv4len + 2
		_, err := io.ReadFull(conn, addr[2:n])
		if err != nil {
			return nil, err
		}

		return addr[:n], nil
	case AddrTypeDomain:
		n := 1 + 1 + int(addr[1]) + 2
		_, err := io.ReadFull(conn, addr[2:n])
		if err != nil {
			return nil, err
		}

		return addr[:n], nil
	case AddrTypeIPv6:
		n := 1 + net.IPv6len + 2
		_, err := io.ReadFull(conn, addr[2:n])
		if err != nil {
			return nil, err
		}

		return addr[:n], nil
	default:
		return nil, errAddrType(addr[0])
	}
}
