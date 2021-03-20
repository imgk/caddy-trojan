package trojan

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"reflect"
	"time"
	"unsafe"
)

// ByteSliceToString is ...
func ByteSliceToString(b []byte) string {
	ptr := (*reflect.SliceHeader)(unsafe.Pointer(&b))
	hdr := &reflect.StringHeader{
		Data: ptr.Data,
		Len:  ptr.Len,
	}
	return *(*string)(unsafe.Pointer(hdr))
}

// Upstream is ...
type Upstream interface {
	Validate(string) bool
	Consume(int64, int64)
}

// NewUpstream is ...
func NewUpstream(ss []string, s string, encoding bool) (Upstream, error) {
	if s == "" {
		u := &LocalUpstream{Users: make(map[string]struct{})}
		b := [HeaderLen]byte{}
		for _, v := range ss {
			GenKey(v, b[:])
			if encoding {
				u.Users[fmt.Sprintf("Basic %v", base64.StdEncoding.EncodeToString(b[:]))] = struct{}{}
			} else {
				u.Users[string(b[:])] = struct{}{}
			}
		}
		return u, nil
	}
	u := &RemoteUpstream{Users: make(map[string]struct{})}
	b := [HeaderLen]byte{}
	for _, v := range ss {
		GenKey(v, b[:])
		if encoding {
			u.Users[fmt.Sprintf("Basic %v", base64.StdEncoding.EncodeToString(b[:]))] = struct{}{}
		} else {
			u.Users[string(b[:])] = struct{}{}
		}
	}
	return u, nil
}

// LocalUpstream is ...
type LocalUpstream struct {
	// Users is ...
	Users map[string]struct{}
}

// Validate is ...
func (u *LocalUpstream) Validate(s string) bool {
	_, ok := u.Users[s]
	return ok
}

// Consume is ...
func (u *LocalUpstream) Consume(n1, n2 int64) {}

// RemoteUpstream is ...
type RemoteUpstream struct {
	// Client is ...
	http.Client
	// Users is ...
	Users map[string]struct{}
	// URL is ...
	URL string
}

// Validate is ...
func (u *RemoteUpstream) Validate(s string) bool {
	_, ok := u.Users[s]
	return ok
}

// Consume is ...
func (u *RemoteUpstream) Consume(n1, n2 int64) {}

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
	hash := sha256.Sum224([]byte(s))
	hex.Encode(key, hash[:])
}

// Handle is ...
func Handle(r io.Reader, w io.Writer) (int64, int64, error) {
	b := [1 + MaxAddrLen + 2]byte{}

	// read command
	if _, err := io.ReadFull(r, b[:1]); err != nil {
		return 0, 0, fmt.Errorf("read command error: %w", err)
	}

	// read address
	addr, err := ReadAddrBuffer(r, b[3:])
	if err != nil {
		return 0, 0, fmt.Errorf("read addr error: %w", err)
	}

	// read 0x0d, 0x0a
	if _, err := io.ReadFull(r, b[1:3]); err != nil {
		return 0, 0, fmt.Errorf("read 0x0d 0x0a error: %w", err)
	}

	switch b[0] {
	case CmdConnect:
		tgt, err := ResolveTCPAddr(addr)
		if err != nil {
			return 0, 0, fmt.Errorf("resolve tcp addr error: %w", err)
		}
		nr, nw, err := HandleTCP(r, w, tgt)
		if err != nil {
			return nr, nw, fmt.Errorf("handle tcp error: %w", err)
		}
		return nr, nw, nil
	case CmdAssociate:
		nr, nw, err := HandleUDP(r, w)
		if err != nil {
			return nr, nw, fmt.Errorf("handle udp error: %w", err)
		}
		return nr, nw, nil
	default:
	}
	return 0, 0, errors.New("command error")
}

// HandleTCP is ...
// trojan TCP stream
func HandleTCP(r io.Reader, w io.Writer, addr *net.TCPAddr) (int64, int64, error) {
	rc, err := net.DialTCP("tcp", nil, addr)
	if err != nil {
		return 0, 0, err
	}
	defer rc.Close()

	type Result struct {
		Num int64
		Err error
	}

	errCh := make(chan Result, 1)
	go func(rc *net.TCPConn, r io.Reader, errCh chan Result) {
		nw, err := io.Copy(io.Writer(rc), r)
		if err == nil || errors.Is(err, os.ErrDeadlineExceeded) {
			rc.CloseWrite()
			errCh <- Result{Num: nw, Err: nil}
			return
		}
		rc.SetReadDeadline(time.Now())
		errCh <- Result{Num: nw, Err: err}
	}(rc, r, errCh)

	nr, nw, err := func(rc *net.TCPConn, w io.Writer, errCh chan Result) (int64, int64, error) {
		nr, err := io.Copy(w, io.Reader(rc))
		if err == nil || errors.Is(err, os.ErrDeadlineExceeded) {
			type CloseWriter interface {
				CloseWrite() error
			}
			if closer, ok := w.(CloseWriter); ok {
				closer.CloseWrite()
			}
			r := <-errCh
			return nr, r.Num, r.Err
		}
		rc.SetWriteDeadline(time.Now())
		rc.CloseWrite()
		r := <-errCh
		return nr, r.Num, err
	}(rc, w, errCh)

	return nr, nw, err
}

// HandleUDP is ...
// [AddrType(1 byte)][Addr(max 256 byte)][Port(2 byte)][Len(2 byte)][0x0d, 0x0a][Data(max 65535 byte)]
func HandleUDP(r io.Reader, w io.Writer) (int64, int64, error) {
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

	nr, nw, err := func(rc *net.UDPConn, w io.Writer, errCh chan Result, timeout time.Duration) (nr, nw int64, err error) {
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
			nr += 4 + int64(n) + l

			if _, ew := w.Write(b[MaxAddrLen-l : MaxAddrLen+4+n]); ew != nil {
				err = ew
				break
			}
		}
		rc.SetWriteDeadline(time.Now())

		if errors.Is(err, io.EOF) || errors.Is(err, os.ErrDeadlineExceeded) {
			r := <-errCh
			return nr, r.Num, r.Err
		}
		r := <-errCh
		return nr, r.Num, err
	}(rc, w, errCh, time.Minute*10)

	return nr, nw, err
}
