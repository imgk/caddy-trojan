package trojan

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"github.com/xtaci/smux"
	"go.uber.org/zap"
)

const (
	HexLen        = 56
	MaxBufferSize = 1024 * 32

	cmdConnect   = 1
	cmdAssocaite = 3
	cmdSmux      = 0x7f
	cmdSmux2     = 0x8f
)

var byteBuffer = sync.Pool{New: newBuffer}

func newBuffer() interface{} {
	return make([]byte, MaxBufferSize)
}

func GenKey(s string, key []byte) {
	hash := sha256.Sum224([]byte(s))
	hex.Encode(key, hash[:])
}

func Handle(conn net.Conn, usr User) error {
	return HandleConn(conn, &usr)
}

func HandleConn(conn net.Conn, usr *User) (err error) {
	defer conn.Close()

	b := [1 + 2 + MaxAddrLen]byte{}

	if _, er := io.ReadFull(conn, b[:1]); er != nil {
		err = fmt.Errorf("read command error: %w", er)
		return
	}

	addr, er := ReadAddrBuffer(conn, b[3:])
	if er != nil {
		err = fmt.Errorf("read addr error: %w", er)
		return
	}

	if _, er := io.ReadFull(conn, b[1:3]); er != nil {
		err = fmt.Errorf("read 0x0d 0x0a error: %w", er)
		return
	}

	switch b[0] {
	case cmdConnect:
		nr, nw, er := HandleTCP(conn, addr.String())
		usr.Consume(nr, nw)
		if er != nil {
			err = fmt.Errorf("handle tcp error: %w", er)
		}
	case cmdAssocaite:
		nr, nw, er := HandleUDP(conn)
		usr.Consume(nr, nw)
		if er != nil {
			err = fmt.Errorf("handle udp error: %w", er)
		}
	case cmdSmux, cmdSmux2:
		er := HandleMux(conn, usr, b[0])
		if er != nil {
			err = fmt.Errorf("handle mux error: %w", er)
		}
	default:
		err = fmt.Errorf("command error")
	}
	return
}

func HandleMux(conn net.Conn, usr *User, ver byte) (err error) {
	sess, er := smux.Server(conn, &smux.Config{
		Version:           int(ver>>4) - 6,
		KeepAliveInterval: 10 * time.Second,
		KeepAliveTimeout:  30 * time.Second,
		MaxFrameSize:      32768,
		MaxReceiveBuffer:  4194304,
		MaxStreamBuffer:   65536,
	})
	if er != nil {
		err = fmt.Errorf("new smux server error: %w", er)
		return
	}
	defer sess.Close()

	wg := sync.WaitGroup{}
	for {
		stream, er := sess.AcceptStream()
		if er != nil {
			if sess.IsClosed() || errors.Is(er, io.EOF) || errors.Is(er, smux.ErrInvalidProtocol) {
				break
			}
			err = fmt.Errorf("accept stream error: %w", er)
			break
		}

		wg.Add(1)
		go HandleStream(stream, usr, &wg)
	}

	wg.Wait()
	return
}

func HandleStream(conn net.Conn, usr *User, wg *sync.WaitGroup) (err error) {
	defer func(conn net.Conn, usr *User, wg *sync.WaitGroup) {
		if err != nil {
			if !errors.Is(err, smux.ErrInvalidProtocol) {
				usr.logger.Error(usr.Name, zap.Error(err))
			}
		}
		conn.Close()
		wg.Done()
	}(conn, usr, wg)

	b := [1 + MaxAddrLen]byte{}

	if _, er := io.ReadFull(conn, b[:1]); er != nil {
		err = fmt.Errorf("read mux command error: %w", er)
		return
	}

	addr, er := ReadAddrBuffer(conn, b[1:])
	if er != nil {
		err = fmt.Errorf("read mux addr error: %w", er)
		return
	}

	switch b[0] {
	case cmdConnect:
		nr, nw, er := HandleTCP(conn, addr.String())
		usr.Consume(nr, nw)
		if er != nil {
			err = fmt.Errorf("handle mux tcp error: %w", er)
		}
	case cmdAssocaite:
		nr, nw, er := HandleUDP(conn)
		usr.Consume(nr, nw)
		if er != nil {
			err = fmt.Errorf("handle mux udp error: %w", er)
		}
	default:
		err = fmt.Errorf("mux command error")
	}
	return
}

type data struct {
	num int64
	err error
}

// Handle trojan TCP stream
func HandleTCP(conn net.Conn, addr string) (n1 int64, n2 int64, err error) {
	rc, err := net.Dial("tcp", addr)
	if err != nil {
		return
	}
	defer rc.Close()

	n1, n2, err = relay(NewDuplexConn(conn), rc.(*net.TCPConn))
	if err != nil {
		if ne := net.Error(nil); errors.As(err, &ne) {
			if ne.Timeout() {
				err = nil
				return
			}
		}
		if errors.Is(err, io.ErrClosedPipe) || errors.Is(err, io.EOF) {
			err = nil
			return
		}
		err = fmt.Errorf("relay error: %w", err)
	}

	return
}

type CloseReader interface {
	CloseRead() error
}

type CloseWriter interface {
	CloseWrite() error
}

type DuplexConn interface {
	net.Conn
	CloseReader
	CloseWriter
}

func NewDuplexConn(conn net.Conn) DuplexConn {
	_, ok := conn.(DuplexConn)
	if ok {
		return conn.(DuplexConn)
	}
	return duplexConn{Conn: conn}
}

type duplexConn struct {
	net.Conn
}

func (c duplexConn) ReadFrom(r io.Reader) (int64, error) {
	if rt, ok := c.Conn.(io.ReaderFrom); ok {
		return rt.ReadFrom(r)
	}
	return Copy(c.Conn, r)
}

func (c duplexConn) WriteTo(w io.Writer) (int64, error) {
	if wt, ok := c.Conn.(io.WriterTo); ok {
		return wt.WriteTo(w)
	}
	return Copy(w, c.Conn)
}

func (c duplexConn) CloseRead() error {
	if close, ok := c.Conn.(CloseReader); ok {
		return close.CloseRead()
	}
	return c.Conn.SetReadDeadline(time.Now())
}

func (c duplexConn) CloseWrite() error {
	if close, ok := c.Conn.(CloseWriter); ok {
		return close.CloseWrite()
	}
	return c.Conn.SetWriteDeadline(time.Now())
}

func relay(c, rc DuplexConn) (int64, int64, error) {
	ch := make(chan data, 1)
	go relay2(c, rc, ch)

	n, err := Copy(rc, c)
	if err != nil {
		rc.Close()
		c.Close()
	} else {
		rc.CloseWrite()
		c.CloseRead()
	}

	r := <-ch

	if err == nil {
		err = r.err
	}
	if errors.Is(err, os.ErrDeadlineExceeded) || errors.Is(err, smux.ErrTimeout) {
		err = nil
	}

	return n, r.num, err
}

func relay2(c, rc DuplexConn, ch chan data) {
	n, err := Copy(c, rc)
	if err != nil {
		c.Close()
		rc.Close()
	} else {
		c.CloseWrite()
		rc.CloseRead()
	}

	ch <- data{num: n, err: err}
}

func Copy(w io.Writer, r io.Reader) (n int64, err error) {
	if c, ok := w.(duplexConn); ok {
		w = c.Conn
	}
	if c, ok := r.(duplexConn); ok {
		r = c.Conn
	}
	if wt, ok := r.(io.WriterTo); ok {
		return wt.WriteTo(w)
	}
	if rt, ok := w.(io.ReaderFrom); ok {
		if _, ok := rt.(*net.TCPConn); !ok {
			return rt.ReadFrom(r)
		}
	}

	b := byteBuffer.Get().([]byte)
	defer byteBuffer.Put(b)

	for {
		nr, er := r.Read(b)
		if nr > 0 {
			nw, ew := w.Write(b[:nr])
			n += int64(nw)
			if ew != nil {
				err = ew
				break
			}
			if nr != nw {
				err = io.ErrShortWrite
				break
			}
		}
		if er != nil {
			if errors.Is(er, io.EOF) {
				break
			}
			err = er
			break
		}
	}
	return n, err
}

// handle trojan UDP packet
// [AddrType(1 byte)][Addr(max 256 byte)][Port(2 byte)][Len(2 byte)][0x0d, 0x0a][Data(max 65536 byte)]
func HandleUDP(conn net.Conn) (int64, int64, error) {
	rc, err := net.ListenPacket("udp", "")
	if err != nil {
		return 0, 0, err
	}

	ch := make(chan data, 1)
	go Copy2(conn, rc, time.Minute*5, ch)

	before := ""
	udpAddr := (*net.UDPAddr)(nil)

	n := int64(0)
	b := byteBuffer.Get().([]byte)
	for {
		raddr, er := ReadAddrBuffer(conn, b)
		if er != nil {
			if ne := net.Error(nil); errors.As(er, &ne) {
				if ne.Timeout() {
					break
				}
			}
			if errors.Is(er, smux.ErrTimeout) || errors.Is(er, io.ErrClosedPipe) || errors.Is(er, io.EOF) {
				break
			}
			err = fmt.Errorf("read addr error: %w", er)
			break
		}
		if str := string(raddr[:]); before != str {
			tt, er := ResolveUDPAddr(raddr)
			if er != nil {
				err = fmt.Errorf("resolve target error: %w", er)
				break
			}
			before = str
			udpAddr = tt
		}

		nr := len(raddr)

		if _, er := io.ReadFull(conn, b[nr:nr+4]); er != nil {
			if ne := net.Error(nil); errors.As(er, &ne) {
				if ne.Timeout() {
					break
				}
			}
			if errors.Is(er, smux.ErrTimeout) || errors.Is(er, io.ErrClosedPipe) {
				break
			}
			err = fmt.Errorf("read size info error: %w", er)
			break
		}

		nr += (int(b[nr])<<8 | int(b[nr+1])) + 4
		n += int64(nr)

		buf := b[len(raddr)+4:nr]
		if _, er := io.ReadFull(conn, buf); er != nil {
			if ne := net.Error(nil); errors.As(er, &ne) {
				if ne.Timeout() {
					break
				}
			}
			if errors.Is(er, smux.ErrTimeout) || errors.Is(er, io.ErrClosedPipe) {
				break
			}
			err = fmt.Errorf("read data error: %w", er)
			break
		}

		rc.SetWriteDeadline(time.Now().Add(time.Minute * 5))
		if _, er := rc.WriteTo(buf, udpAddr); er != nil {
			if ne := net.Error(nil); errors.As(er, &ne) {
				if ne.Timeout() {
					break
				}
			}
			if errors.Is(err, os.ErrDeadlineExceeded) {
				break
			}
			err = fmt.Errorf("writeto error: %w", er)
			break
		}
	}
	byteBuffer.Put(b)

	rc.SetReadDeadline(time.Now())
	d := <-ch

	if err == nil {
		err = d.err
	}

	return n, d.num, err
}

func Copy2(conn net.Conn, rc net.PacketConn, timeout time.Duration, ch chan data) {
	defer rc.Close()

	d := data{num: 0, err: nil}

	b := byteBuffer.Get().([]byte)
	b[MaxAddrLen+2] = 0x0d
	b[MaxAddrLen+3] = 0x0a
	for {
		rc.SetReadDeadline(time.Now().Add(timeout))
		n, src, err := rc.ReadFrom(b[MaxAddrLen+4:])
		if err != nil {
			if ne := net.Error(nil); errors.As(err, &ne) {
				if ne.Timeout() {
					break
				}
			}
			if errors.Is(err, io.EOF) || errors.Is(err, os.ErrDeadlineExceeded) {
				break
			}
			d.err = fmt.Errorf("readfrom error: %w", err)
			break
		}

		b[MaxAddrLen] = byte(n >> 8)
		b[MaxAddrLen+1] = byte(n)

		na := func(bb []byte, addr *net.UDPAddr) int64 {
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
		}(b[:MaxAddrLen], src.(*net.UDPAddr))
		d.num += 4 + int64(n) + na

		if _, err := conn.Write(b[MaxAddrLen-na : MaxAddrLen+4+n]); err != nil {
			if ne := net.Error(nil); errors.As(err, &ne) {
				if ne.Timeout() {
					break
				}
			}
			d.err = fmt.Errorf("write packet error: %w", err)
			break
		}
	}
	byteBuffer.Put(b)

	ch <- d
	return
}

type emptyReader struct{}

func (emptyReader) Read(b []byte) (int, error) {
	return 0, io.EOF
}

// implement net.Conn
type WebSocketConn struct {
	*websocket.Conn
	Reader io.Reader
}

func NewWebSocketConn(conn *websocket.Conn) *WebSocketConn {
	return &WebSocketConn{
		Conn:   conn,
		Reader: emptyReader{},
	}
}

func (conn *WebSocketConn) Read(b []byte) (int, error) {
	n, err := conn.Reader.Read(b)
	if n > 0 {
		return n, nil
	}

	_, conn.Reader, err = conn.Conn.NextReader()
	if err != nil {
		if er := (*websocket.CloseError)(nil); errors.As(err, &er) {
			return 0, io.EOF
		}
		return 0, err
	}

	n, err = conn.Reader.Read(b)
	return n, nil
}

func (conn *WebSocketConn) Write(b []byte) (int, error) {
	err := conn.Conn.WriteMessage(websocket.BinaryMessage, b)
	if err != nil {
		if er := (*websocket.CloseError)(nil); errors.As(err, &er) {
			return 0, io.EOF
		}
		return 0, err
	}
	return len(b), nil
}

func (conn *WebSocketConn) SetDeadline(t time.Time) error {
	conn.SetReadDeadline(t)
	conn.SetWriteDeadline(t)
	return nil
}

func (conn *WebSocketConn) Close() (err error) {
	err = conn.Conn.WriteControl(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""), time.Now().Add(time.Second*5))
	conn.Conn.Close()
	return
}
