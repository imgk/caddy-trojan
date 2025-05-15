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

const HeaderLen = 56

const (
	CmdConnect   = 1
	CmdAssociate = 3
)

func GenKey(s string, key []byte) {
	hash := sha256.Sum224(x.StringToByteSlice(s))
	hex.Encode(key, hash[:])
}

type Dialer interface {
	Dial(string, string) (net.Conn, error)
	ListenPacket(string, string) (net.PacketConn, error)
}

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
