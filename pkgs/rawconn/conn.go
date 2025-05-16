package rawconn

import (
	"bytes"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"reflect"
	"unsafe"
)

func RewindConn(conn net.Conn, read []byte) net.Conn {
	if tlsConn, ok := conn.(*tls.Conn); ok {
		var (
			tlsInput, _ = reflect.TypeOf(tls.Conn{}).FieldByName("input")
			input       = (*bytes.Reader)(unsafe.Add(unsafe.Pointer(tlsConn), tlsInput.Offset))
			remaining   = input.Len()
			size        = int(input.Size())
			buffered    = len(read)
		)
		if buffered <= size {
			_, _ = input.Seek(0, 0)
		} else {
			buf := make([]byte, buffered+remaining)
			copy(buf, read)
			_, _ = input.Read(buf[buffered:])
			input.Reset(buf)
		}
		return tlsConn
	} else {
		return NewConn(conn, read)
	}
}

type conn struct {
	net.Conn
	Reader bytes.Reader
}

func NewConn(nc net.Conn, buf []byte) net.Conn {
	c := &conn{
		Conn: nc,
	}
	c.Reader.Reset(buf)
	return c
}

func (c *conn) Read(b []byte) (int, error) {
	if c.Reader.Size() == 0 {
		return c.Conn.Read(b)
	}
	n, err := c.Reader.Read(b)
	if errors.Is(err, io.EOF) {
		c.Reader.Reset([]byte{})
		return n, nil
	}
	return n, err
}

func (c *conn) CloseWrite() error {
	if cc, ok := c.Conn.(*net.TCPConn); ok {
		return cc.CloseWrite()
	}
	if cw, ok := c.Conn.(interface {
		CloseWrite() error
	}); ok {
		return cw.CloseWrite()
	}
	return errors.New("not supported")
}
