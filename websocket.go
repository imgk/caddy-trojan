package trojan

import (
	"errors"
	"io"
	"time"

	"github.com/gorilla/websocket"
)

// eofReader is ...
type eofReader struct{}

// Read is ...
func (*eofReader) Read(b []byte) (int, error) {
	return 0, io.EOF
}

// wsConn is ...
type wsConn struct {
	*websocket.Conn
	r io.Reader
}

// Read is ...
func (c *wsConn) Read(b []byte) (int, error) {
	n, err := c.r.Read(b)
	if n > 0 {
		return n, nil
	}

	_, c.r, err = c.Conn.NextReader()
	if err != nil {
		if ce := (*websocket.CloseError)(nil); errors.As(err, &ce) {
			return 0, io.EOF
		}
		return 0, err
	}

	n, err = c.r.Read(b)
	return n, nil
}

// Write is ...
func (c *wsConn) Write(b []byte) (int, error) {
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
func (c *wsConn) Close() error {
	msg := websocket.FormatCloseMessage(websocket.CloseNormalClosure, "")
	c.Conn.WriteControl(websocket.CloseMessage, msg, time.Now().Add(time.Second*5))
	return c.Conn.Close()
}
