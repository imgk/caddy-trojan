package websocket

import (
	"errors"
	"io"
	"net/http"
	"time"

	"github.com/gorilla/websocket"
)

// Upgrader is ...
type Upgrader struct {
	websocket.Upgrader
}

// IsWebSocketUpgrade is ...
func IsWebSocketUpgrade(r *http.Request) bool {
	return websocket.IsWebSocketUpgrade(r)
}

// eofReader is ...
type eofReader struct{}

// Read is ...
func (*eofReader) Read(b []byte) (int, error) {
	return 0, io.EOF
}

// Conn is ...
type Conn struct {
	*websocket.Conn
	Reader io.Reader
}

// NewConn is ...
func NewConn(c *websocket.Conn) *Conn {
	return &Conn{
		Conn:   c,
		Reader: (*eofReader)(nil),
	}
}

// Read is ...
func (c *Conn) Read(b []byte) (n int, err error) {
	n, _ = c.Reader.Read(b)
	if n > 0 {
		return n, nil
	}

	_, c.Reader, err = c.Conn.NextReader()
	if err != nil {
		if ce := (*websocket.CloseError)(nil); errors.As(err, &ce) {
			return 0, io.EOF
		}
		return 0, err
	}

	n, _ = c.Reader.Read(b)
	return n, nil
}

// Write is ...
func (c *Conn) Write(b []byte) (int, error) {
	err := c.Conn.WriteMessage(websocket.BinaryMessage, b)
	if err != nil {
		if ce := (*websocket.CloseError)(nil); errors.As(err, &ce) {
			return 0, io.EOF
		}
		return 0, err
	}
	return len(b), nil
}

// Close is ...
func (c *Conn) Close() error {
	msg := websocket.FormatCloseMessage(websocket.CloseNormalClosure, "")
	c.Conn.WriteControl(websocket.CloseMessage, msg, time.Now().Add(time.Second*5))
	return c.Conn.Close()
}
