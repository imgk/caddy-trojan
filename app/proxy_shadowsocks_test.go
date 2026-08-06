package app

import (
	"errors"
	"net"
	"testing"
)

func TestShadowsocksProxyDialReturnsUpstreamError(t *testing.T) {
	t.Parallel()

	upstreamErr := errors.New("upstream unavailable")
	proxy := &ShadowsocksProxy{
		Server: "127.0.0.1:8388",
		proxy:  dialErrorProxy{err: upstreamErr},
	}

	conn, err := proxy.Dial("tcp", "example.com:443")

	if conn != nil {
		_ = conn.Close()
		t.Fatal("Dial returned a connection when the upstream dial failed")
	}
	if !errors.Is(err, upstreamErr) {
		t.Fatalf("Dial error = %v, want upstream error %v", err, upstreamErr)
	}
}

type dialErrorProxy struct {
	err error
}

func (p dialErrorProxy) Close() error {
	return nil
}

func (p dialErrorProxy) Dial(string, string) (net.Conn, error) {
	return nil, p.err
}

func (p dialErrorProxy) ListenPacket(string, string) (net.PacketConn, error) {
	return nil, p.err
}
