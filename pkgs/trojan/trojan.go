package trojan

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"time"

	"github.com/imgk/caddy-trojan/pkgs/socks"
	"github.com/imgk/caddy-trojan/pkgs/x"
)

// HeaderLen is ...
const HeaderLen = 56

const (
	// CmdConnect is ...
	CmdConnect = 1
	// CmdAssociate is ...
	CmdAssociate = 3
)

// GenKey is ...
func GenKey(s string, key []byte) {
	hash := sha256.Sum224(x.StringToByteSlice(s))
	hex.Encode(key, hash[:])
}

// Handle is ...
func Handle(r io.Reader, w io.Writer) (int64, int64, error) {
	return HandleWithDialer(r, w, (*netDialer)(nil))
}

// Dialer is ...
type Dialer interface {
	// Dial is ...
	Dial(string, string) (net.Conn, error)
	// ListenPacket is ...
	ListenPacket(string, string) (net.PacketConn, error)
}

type netDialer struct{}

func (*netDialer) Dial(network, addr string) (net.Conn, error) {
	return net.Dial(network, addr)
}

func (*netDialer) ListenPacket(network, addr string) (net.PacketConn, error) {
	return net.ListenPacket(network, addr)
}

// HandleWithDialer is ...
func HandleWithDialer(r io.Reader, w io.Writer, d Dialer) (int64, int64, error) {
	b := [1 + socks.MaxAddrLen + 2]byte{}

	// read command
	if _, err := io.ReadFull(r, b[:1]); err != nil {
		return 0, 0, fmt.Errorf("read command error: %w", err)
	}
	if b[0] != CmdConnect && b[0] != CmdAssociate {
		return 0, 0, errors.New("command error")
	}

	// read address
	addr, err := socks.ReadAddrBuffer(r, b[3:])
	if err != nil {
		return 0, 0, fmt.Errorf("read addr error: %w", err)
	}

	// read 0x0d, 0x0a
	if _, err := io.ReadFull(r, b[1:3]); err != nil {
		return 0, 0, fmt.Errorf("read 0x0d 0x0a error: %w", err)
	}

	switch b[0] {
	case CmdConnect:
		nr, nw, err := HandleTCP(r, w, addr, d)
		if err != nil {
			return nr, nw, fmt.Errorf("handle tcp error: %w", err)
		}
		return nr, nw, nil
	case CmdAssociate:
		nr, nw, err := HandleUDP(r, w, time.Minute*10, d)
		if err != nil {
			return nr, nw, fmt.Errorf("handle udp error: %w", err)
		}
		return nr, nw, nil
	default:
	}
	return 0, 0, errors.New("command error")
}
