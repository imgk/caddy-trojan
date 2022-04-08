package grpc

import (
	"bufio"
	"encoding/binary"
	"io"
	"net"
	"net/http"
	"strings"
)

// based on https://github.com/grpc/grpc-go/blob/master/internal/transport/handler_server.go and https://github.com/Dreamacro/clash/blob/master/transport/gun/gun.go

const (
	grpcContentType = "application/grpc"
)

func IsGRPC(w http.ResponseWriter, r *http.Request) bool {
	if _, ok := w.(http.Flusher); !ok {
		return false
	}
	if r.Method != http.MethodPost {
		return false
	}
	if r.ProtoMajor != 2 {
		return false
	}
	if !strings.HasPrefix(r.Header.Get("Content-Type"), grpcContentType) {
		return false
	}
	return true
}

type Conn struct {
	closer        io.Closer
	bufReadWriter *bufio.ReadWriter
	remaining     int
	header        http.Header
	flusher       http.Flusher
	headerWritten bool

	closed bool
}

// GRPC with protobuf is a TLV protocol, 5 bytes header and tlv
// first byte 0 means uncompressed, 1 means compressed, the next four is the payload length of the total message

// 6th byte is the tag, with v2ray's implementation is value 10
// next several bytes is unsigned variables length int
// remaining is the actual payload
func NewConn(request *http.Request, responseWriter http.ResponseWriter) *Conn {
	return &Conn{
		closer:        request.Body,
		bufReadWriter: bufio.NewReadWriter(bufio.NewReader(request.Body), bufio.NewWriter(responseWriter)),
		header:        responseWriter.Header(),
		flusher:       responseWriter.(http.Flusher),
	}
}

func (c *Conn) Read(p []byte) (n int, err error) {
	if c.closed {
		return 0, net.ErrClosed
	}

	if c.remaining == 0 {
		_, err = c.bufReadWriter.Discard(6)
		if err != nil {
			return 0, err
		}

		var protobufPayloadLen uint64
		protobufPayloadLen, err = binary.ReadUvarint(c.bufReadWriter)
		if err != nil {
			return 0, err
		}

		c.remaining = int(protobufPayloadLen)
	}

	if c.remaining < len(p) {
		p = p[:c.remaining]
	}
	n, err = io.ReadFull(c.bufReadWriter, p)
	c.remaining -= n
	return
}

func (c *Conn) Write(p []byte) (n int, err error) {
	if c.closed {
		return 0, net.ErrClosed
	}

	if !c.headerWritten {
		c.header.Set("Content-Type", grpcContentType)
		c.header.Add("Trailer", "Grpc-Status")
		c.header.Add("Trailer", "Grpc-Message")
		c.header.Add("Trailer", "Grpc-Status-Details-Bin")
		c.headerWritten = true
	}
	n = len(p)
	header := make([]byte, 16)
	header[0] = 0
	header[5] = 10
	payloadLen := binary.PutUvarint(header[6:], uint64(n)) + 1 + n
	binary.BigEndian.PutUint32(header[1:5], uint32(payloadLen))
	_, _ = c.bufReadWriter.Write(header[:payloadLen+5-n])
	_, _ = c.bufReadWriter.Write(p)

	err = c.bufReadWriter.Flush()
	c.flusher.Flush()

	if err != nil {
		n = 0
	}
	return
}

func (c *Conn) Close() error {
	if c.closed {
		return net.ErrClosed
	}

	if !c.headerWritten {
		// http framework will close the underlying tcp connection
		c.header.Set("Connection", "close")
		c.headerWritten = true
	} else {
		c.header.Set("Grpc-Status", "0")
	}
	c.closed = true
	return c.closer.Close()
}
