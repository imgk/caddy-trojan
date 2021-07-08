package trojan

import (
	"errors"
	"io"
	"net"
	"os"
	"time"
)

func ioCopy(w io.Writer, r io.Reader) (n int64, err error) {
	buf := malloc(16 * 1024)
	defer free(buf)
	for {
		nr, er := r.Read(buf)
		if nr > 0 {
			nw, ew := w.Write(buf[0:nr])
			if nw < 0 || nr < nw {
				nw = 0
				if ew == nil {
					ew = errors.New("invalid write result")
				}
			}
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
			if !errors.Is(er, io.EOF) {
				err = er
			}
			break
		}
	}
	return n, err
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
		nr, err := ioCopy(io.Writer(rc), r)
		if err == nil || errors.Is(err, os.ErrDeadlineExceeded) {
			rc.CloseWrite()
			errCh <- Result{Num: nr, Err: nil}
			return
		}
		rc.CloseWrite()
		rc.SetReadDeadline(time.Now())
		errCh <- Result{Num: nr, Err: err}
	}(rc, r, errCh)

	nr, nw, err := func(rc *net.TCPConn, w io.Writer, errCh chan Result) (int64, int64, error) {
		nw, err := ioCopy(w, io.Reader(rc))
		if err == nil || errors.Is(err, os.ErrDeadlineExceeded) {
			if cw, ok := w.(interface {
				CloseWrite() error
			}); ok {
				cw.CloseWrite()
			}
			r := <-errCh
			return r.Num, nw, r.Err
		}
		rc.SetWriteDeadline(time.Now())
		rc.CloseWrite()
		r := <-errCh
		return r.Num, nw, err
	}(rc, w, errCh)

	return nr, nw, err
}
