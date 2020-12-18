package trojan

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"

	"go.uber.org/multierr"
	"go.uber.org/zap"
)

var ErrNotTrojan = errors.New("not a trojan connection")

type User struct {
	Name   string
	admin  *App
	logger *zap.Logger
}

func (usr *User) Consume(n1, n2 int64) (bool, error) {
	return usr.admin.Consume(usr.Name, n1, n2)
}

func (usr *User) SetLogger(logger *zap.Logger) {
	usr.logger = logger
}

func (m *App) CheckConn(conn net.Conn) (usr User, err error) {
	b := [HexLen + 2]byte{}
	if _, er := io.ReadFull(conn, b[:]); er != nil {
		err = fmt.Errorf("read trojan header error: %w", er)
		return
	}

	name := string(b[:HexLen])
	ok, err := m.Query(name)
	if err != nil {
		err = fmt.Errorf("query user error: %w", err)
		return
	}
	if !ok {
		err = ErrNotTrojan
		return
	}

	usr.Name = name
	usr.admin = m
	return
}

type WrappedConn struct {
	net.Conn
	reader io.Reader
}

func NewWrappedConn(conn net.Conn) *WrappedConn {
	return &WrappedConn{Conn: conn, reader: conn}
}

func (conn *WrappedConn) Read(b []byte) (int, error) {
	return conn.reader.Read(b)
}

var readerBuffer = sync.Pool{
	New: func() interface{} { return bufio.NewReader(emptyReader{}) },
}

func (m *App) CheckWrappedConn(conn *WrappedConn) (usr User, err error) {
	r := readerBuffer.Get().(*bufio.Reader)
	r.Reset(conn.Conn)
	b, err := r.ReadBytes('\n')
	defer func(r *bufio.Reader) {
		if err == nil {
			b = nil
		} else {
			if err != ErrNotTrojan {
				readerBuffer.Put(r)
				return
			}
		}
		if n := r.Buffered(); n > 0 {
			bb, _ := r.Peek(n)
			b = append(b, bb...)
		}
		if len(b) > 0 {
			conn.reader = io.MultiReader(bytes.NewReader(b), conn.Conn)
		} else {
			conn.reader = conn.Conn
		}
		readerBuffer.Put(r)
	}(r)
	if err != nil {
		err = fmt.Errorf("read trojan header error: %w", err)
		return
	}
	if len(b) != HexLen+2 {
		err = ErrNotTrojan
		return
	}

	name := string(b[:HexLen])
	ok, err := m.Query(name)
	if err != nil {
		err = fmt.Errorf("query user error: %w", err)
		return
	}
	if !ok {
		err = ErrNotTrojan
		return
	}

	usr.Name = name
	usr.admin = m
	return
}

func (m *App) Query(user string) (bool, error) {
	if _, ok := m.users[user]; ok {
		return true, nil
	}
	return m.QueryRemote(user)
}

func (m *App) QueryRemote(user string) (bool, error) {
	if m.redis == nil {
		return false, nil
	}
	b, err := m.redis.HExists(context.Background(), user, "upload").Result()
	if err != nil {
		return false, nil
	}
	return b, nil
}

func (m *App) Consume(user string, n1, n2 int64) (bool, error) {
	if _, ok := m.users[user]; ok {
		return true, nil
	}
	return m.ConsumeRemote(user, n1, n2)
}

func (m *App) ConsumeRemote(user string, n1, n2 int64) (bool, error) {
	err := multierr.Combine(
		m.redis.HIncrBy(context.Background(), user, "upload", n1).Err(),
		m.redis.HIncrBy(context.Background(), user, "download", n2).Err(),
	)
	if err != nil {
		return true, err
	}
	return true, nil
}

func (m *App) renewUsage() {
	for range m.ticker.C {
		n1, n2, err := NetworkCard(m.NICName).GetUsage()
		if err != nil {
			m.logger.Error("renew usage", zap.Error(err))
		}
		current := n1 + n2
		m.usage = current - m.before
		m.before = current
	}
}
