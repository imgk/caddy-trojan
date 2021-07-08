package socks

import (
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
)

// MaxAddrLen is the maximum length of socks.Addr
const MaxAddrLen = 1 + 1 + 255 + 2

var (
	// ErrInvalidAddrType is ...
	ErrInvalidAddrType = errors.New("invalid address type")
	// ErrInvalidAddrLen is ...
	ErrInvalidAddrLen = errors.New("invalid address length")
)

const (
	// AddrTypeIPv4 is ...
	AddrTypeIPv4 = 1
	// AddrTypeDomain is ...
	AddrTypeDomain = 3
	// AddrTypeIPv6 is ...
	AddrTypeIPv6 = 4
)

// Addr is ...
type Addr struct {
	Addr []byte
}

// Network is ...
func (*Addr) Network() string {
	return "socks"
}

// String is ...
func (addr *Addr) String() string {
	switch addr.Addr[0] {
	case AddrTypeIPv4:
		host := net.IP(addr.Addr[1 : 1+net.IPv4len]).String()
		port := strconv.Itoa(int(addr.Addr[1+net.IPv4len])<<8 | int(addr.Addr[1+net.IPv4len+1]))
		return net.JoinHostPort(host, port)
	case AddrTypeDomain:
		host := string(addr.Addr[2 : 2+addr.Addr[1]])
		port := strconv.Itoa(int(addr.Addr[2+addr.Addr[1]])<<8 | int(addr.Addr[2+addr.Addr[1]+1]))
		return net.JoinHostPort(host, port)
	case AddrTypeIPv6:
		host := net.IP(addr.Addr[1 : 1+net.IPv6len]).String()
		port := strconv.Itoa(int(addr.Addr[1+net.IPv6len])<<8 | int(addr.Addr[1+net.IPv6len+1]))
		return net.JoinHostPort(host, port)
	default:
		return ""
	}
}

// ReadAddr is ....
func ReadAddr(conn io.Reader) (*Addr, error) {
	return ReadAddrBuffer(conn, make([]byte, MaxAddrLen))
}

// ReadAddrBuffer is ...
func ReadAddrBuffer(conn io.Reader, addr []byte) (*Addr, error) {
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

		return &Addr{Addr: addr[:n]}, nil
	case AddrTypeDomain:
		n := 1 + 1 + int(addr[1]) + 2
		_, err := io.ReadFull(conn, addr[2:n])
		if err != nil {
			return nil, err
		}

		return &Addr{Addr: addr[:n]}, nil
	case AddrTypeIPv6:
		n := 1 + net.IPv6len + 2
		_, err := io.ReadFull(conn, addr[2:n])
		if err != nil {
			return nil, err
		}

		return &Addr{Addr: addr[:n]}, nil
	default:
		return nil, ErrInvalidAddrType
	}
}

// ParseAddr is ...
func ParseAddr(addr []byte) (*Addr, error) {
	if len(addr) < 1+1+1+2 {
		return nil, ErrInvalidAddrLen
	}

	switch addr[0] {
	case AddrTypeIPv4:
		n := 1 + net.IPv4len + 2
		if len(addr) < n {
			return nil, ErrInvalidAddrLen
		}

		return &Addr{Addr: addr[:n]}, nil
	case AddrTypeDomain:
		n := 1 + 1 + int(addr[1]) + 2
		if len(addr) < n {
			return nil, ErrInvalidAddrLen
		}

		return &Addr{Addr: addr[:n]}, nil
	case AddrTypeIPv6:
		n := 1 + net.IPv6len + 2
		if len(addr) < n {
			return nil, ErrInvalidAddrLen
		}

		return &Addr{Addr: addr[:n]}, nil
	default:
		return nil, ErrInvalidAddrType
	}
}

// ResolveTCPAddr is ...
func ResolveTCPAddr(addr *Addr) (*net.TCPAddr, error) {
	switch addr.Addr[0] {
	case AddrTypeIPv4:
		host := net.IP(addr.Addr[1 : 1+net.IPv4len])
		port := int(addr.Addr[1+net.IPv4len])<<8 | int(addr.Addr[1+net.IPv4len+1])
		return &net.TCPAddr{IP: host, Port: port}, nil
	case AddrTypeDomain:
		return net.ResolveTCPAddr("tcp", addr.String())
	case AddrTypeIPv6:
		host := net.IP(addr.Addr[1 : 1+net.IPv6len])
		port := int(addr.Addr[1+net.IPv6len])<<8 | int(addr.Addr[1+net.IPv6len+1])
		return &net.TCPAddr{IP: host, Port: port}, nil
	default:
		return nil, fmt.Errorf("address type (%v) error", addr.Addr[0])
	}
}

// ResolveUDPAddr is ...
func ResolveUDPAddr(addr *Addr) (*net.UDPAddr, error) {
	switch addr.Addr[0] {
	case AddrTypeIPv4:
		host := net.IP(addr.Addr[1 : 1+net.IPv4len])
		port := int(addr.Addr[1+net.IPv4len])<<8 | int(addr.Addr[1+net.IPv4len+1])
		return &net.UDPAddr{IP: host, Port: port}, nil
	case AddrTypeDomain:
		return net.ResolveUDPAddr("udp", addr.String())
	case AddrTypeIPv6:
		host := net.IP(addr.Addr[1 : 1+net.IPv6len])
		port := int(addr.Addr[1+net.IPv6len])<<8 | int(addr.Addr[1+net.IPv6len+1])
		return &net.UDPAddr{IP: host, Port: port}, nil
	default:
		return nil, fmt.Errorf("address type (%v) error", addr.Addr[0])
	}
}

// ResolveAddr is ...
func ResolveAddr(addr net.Addr) (*Addr, error) {
	if a, ok := addr.(*Addr); ok {
		return a, nil
	}
	return ResolveAddrBuffer(addr, make([]byte, MaxAddrLen))
}

// ResolveAddrBuffer is ...
func ResolveAddrBuffer(addr net.Addr, b []byte) (*Addr, error) {
	if nAddr, ok := addr.(*net.TCPAddr); ok {
		if ipv4 := nAddr.IP.To4(); ipv4 != nil {
			b[0] = AddrTypeIPv4
			copy(b[1:], ipv4)
			b[1+net.IPv4len] = byte(nAddr.Port >> 8)
			b[1+net.IPv4len+1] = byte(nAddr.Port)

			return &Addr{Addr: b[:1+net.IPv4len+2]}, nil
		}
		ipv6 := nAddr.IP.To16()

		b[0] = AddrTypeIPv6
		copy(b[1:], ipv6)
		b[1+net.IPv6len] = byte(nAddr.Port >> 8)
		b[1+net.IPv6len+1] = byte(nAddr.Port)

		return &Addr{Addr: b[:1+net.IPv6len+2]}, nil
	}

	if nAddr, ok := addr.(*net.UDPAddr); ok {
		if ipv4 := nAddr.IP.To4(); ipv4 != nil {
			b[0] = AddrTypeIPv4
			copy(b[1:], ipv4)
			b[1+net.IPv4len] = byte(nAddr.Port >> 8)
			b[1+net.IPv4len+1] = byte(nAddr.Port)

			return &Addr{Addr: b[:1+net.IPv4len+2]}, nil
		}
		ipv6 := nAddr.IP.To16()

		b[0] = AddrTypeIPv6
		copy(b[1:], ipv6)
		b[1+net.IPv6len] = byte(nAddr.Port >> 8)
		b[1+net.IPv6len+1] = byte(nAddr.Port)

		return &Addr{Addr: b[:1+net.IPv6len+2]}, nil
	}

	if nAddr, ok := addr.(*Addr); ok {
		copy(b, nAddr.Addr)
		return &Addr{Addr: b[:len(nAddr.Addr)]}, nil
	}

	return nil, ErrInvalidAddrType
}
