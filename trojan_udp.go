package trojan

import (
	"bytes"
	"errors"
	"io"
	"net"
	"os"
	"time"
)

// HandleUDP is ...
// [AddrType(1 byte)][Addr(max 256 byte)][Port(2 byte)][Len(2 byte)][0x0d, 0x0a][Data(max 65535 byte)]
func HandleUDP(r io.Reader, w io.Writer, timeout time.Duration) (int64, int64, error) {
	rc, err := net.ListenUDP("udp", nil)
	if err != nil {
		return 0, 0, err
	}
	defer rc.Close()

	type Result struct {
		Num int64
		Err error
	}

	errCh := make(chan Result, 1)
	go func(rc *net.UDPConn, r io.Reader, errCh chan Result) (nr int64, err error) {
		defer func() {
			if errors.Is(err, io.EOF) || errors.Is(err, os.ErrDeadlineExceeded) {
				err = nil
			}
			errCh <- Result{Num: nr, Err: err}
		}()

		// save previous address
		bb := make([]byte, MaxAddrLen)
		tt := (*net.UDPAddr)(nil)

		b := make([]byte, 16*1024)
		for {
			raddr, er := ReadAddrBuffer(r, b)
			if er != nil {
				err = er
				break
			}

			l := len(raddr.Addr)

			if !bytes.Equal(bb, raddr.Addr) {
				addr, er := ResolveUDPAddr(raddr)
				if er != nil {
					err = er
					break
				}
				bb = append(bb[:0], raddr.Addr...)
				tt = addr
			}

			if _, er := io.ReadFull(r, b[l:l+4]); er != nil {
				err = er
				break
			}

			l += (int(b[l])<<8 | int(b[l+1]))
			nr += int64(l) + 4

			buf := b[len(raddr.Addr):l]
			if _, er := io.ReadFull(r, buf); er != nil {
				err = er
				break
			}

			if _, ew := rc.WriteToUDP(buf, tt); ew != nil {
				err = ew
				break
			}
		}
		rc.SetReadDeadline(time.Now())
		return
	}(rc, r, errCh)

	nr, nw, err := func(rc *net.UDPConn, w io.Writer, errCh chan Result, timeout time.Duration) (_, nw int64, err error) {
		b := make([]byte, 16*1024)

		b[MaxAddrLen+2] = 0x0d
		b[MaxAddrLen+3] = 0x0a
		for {
			rc.SetReadDeadline(time.Now().Add(timeout))
			n, addr, er := rc.ReadFrom(b[MaxAddrLen+4:])
			if er != nil {
				err = er
				break
			}

			b[MaxAddrLen] = byte(n >> 8)
			b[MaxAddrLen+1] = byte(n)

			l := func(bb []byte, addr *net.UDPAddr) int64 {
				if ipv4 := addr.IP.To4(); ipv4 != nil {
					const offset = MaxAddrLen - (1 + net.IPv4len + 2)
					bb[offset] = AddrTypeIPv4
					copy(bb[offset+1:], ipv4)
					bb[offset+1+net.IPv4len], bb[offset+1+net.IPv4len+1] = byte(addr.Port>>8), byte(addr.Port)
					return 1 + net.IPv4len + 2
				} else {
					const offset = MaxAddrLen - (1 + net.IPv6len + 2)
					bb[offset] = AddrTypeIPv6
					copy(bb[offset+1:], addr.IP.To16())
					bb[offset+1+net.IPv6len], bb[offset+1+net.IPv6len+1] = byte(addr.Port>>8), byte(addr.Port)
					return 1 + net.IPv6len + 2
				}
			}(b[:MaxAddrLen], addr.(*net.UDPAddr))
			nw += 4 + int64(n) + l

			if _, ew := w.Write(b[MaxAddrLen-l : MaxAddrLen+4+n]); ew != nil {
				err = ew
				break
			}
		}
		rc.SetWriteDeadline(time.Now())

		if errors.Is(err, io.EOF) || errors.Is(err, os.ErrDeadlineExceeded) {
			r := <-errCh
			return r.Num, nw, r.Err
		}
		r := <-errCh
		return r.Num, nw, err
	}(rc, w, errCh, timeout)

	return nr, nw, err
}
