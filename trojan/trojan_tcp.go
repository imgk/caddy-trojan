package trojan

import (
	"errors"
	"io"
	"net"
	"os"
	"time"

	"github.com/imgk/memory-go"
)

func copyBuffer(w io.Writer, r io.Reader, buf []byte) (n int64, err error) {
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
func HandleTCP(r io.Reader, w io.Writer, addr net.Addr, d Dialer) (int64, int64, error) {
	rc, err := d.Dial("tcp", addr.String())
	if err != nil {
		return 0, 0, err
	}
	defer rc.Close()

	type Result struct {
		Num int64
		Err error
	}

	errCh := make(chan Result, 0)
	go func(rc net.Conn, r io.Reader, errCh chan Result) {
		ptr, buf := memory.Alloc[byte](32 * 1024)
		defer memory.Free(ptr)

		nr, err := copyBuffer(io.Writer(rc), r, buf)
		if err == nil || errors.Is(err, os.ErrDeadlineExceeded) {
			if cw, ok := rc.(interface {
				CloseWrite() error
			}); ok {
				cw.CloseWrite()
			}
			rc.SetReadDeadline(time.Now())
			errCh <- Result{Num: nr, Err: nil}
			return
		}
		if cw, ok := rc.(interface {
			CloseWrite() error
		}); ok {
			cw.CloseWrite()
		}
		rc.SetReadDeadline(time.Now())
		errCh <- Result{Num: nr, Err: err}
	}(rc, r, errCh)

	nr, nw, err := func(rc net.Conn, w io.Writer, errCh chan Result) (int64, int64, error) {
		ptr, buf := memory.Alloc[byte](32 * 1024)
		defer memory.Free(ptr)

		nw, err := copyBuffer(w, io.Reader(rc), buf)
		if err == nil {
			if cw, ok := w.(interface {
				CloseWrite() error
			}); ok {
				cw.CloseWrite()
			}
			r := <-errCh
			return r.Num, nw, r.Err
		}
		if errors.Is(err, os.ErrDeadlineExceeded) {
			select {
			case r := <-errCh:
				if r.Err == nil {
					for {
						rc.SetReadDeadline(time.Now().Add(time.Minute))
						n, err := copyBuffer(w, io.Reader(rc), buf)
						nw += n
						if n == 0 || !errors.Is(err, os.ErrDeadlineExceeded) {
							break
						}
					}
					return r.Num, nw, r.Err
				}

				if cw, ok := w.(interface {
					CloseWrite() error
				}); ok {
					cw.CloseWrite()
				}
				return r.Num, nw, r.Err
			case <-time.After(time.Minute):
			}
			if cw, ok := w.(interface {
				CloseWrite() error
			}); ok {
				cw.CloseWrite()
			}
			r := <-errCh
			return r.Num, nw, r.Err
		}
		rc.SetWriteDeadline(time.Now())
		if cw, ok := rc.(interface {
			CloseWrite() error
		}); ok {
			cw.CloseWrite()
		}
		r := <-errCh
		return r.Num, nw, err
	}(rc, w, errCh)

	return nr, nw, err
}
