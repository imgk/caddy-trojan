package utils

import (
	"bytes"
	"errors"
	"io"
	"net"
)

// rawConn is ...
type rawConn struct {
	net.Conn
	Reader bytes.Reader
}

// NewRawConn is ...
func NewRawConn(conn net.Conn, buf []byte) net.Conn {
	c := &rawConn{
		Conn: conn,
	}
	c.Reader.Reset(buf)
	return c
}

// Read is ...
func (c *rawConn) Read(b []byte) (int, error) {
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

// CloseWrite is ...
func (c *rawConn) CloseWrite() error {
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
