package app

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/certmagic"
	"go.uber.org/zap"

	"github.com/imgk/caddy-trojan/pkgs/trojan"
	"github.com/imgk/caddy-trojan/pkgs/x"
)

func init() {
	caddy.RegisterModule(CaddyUpstream{})
	caddy.RegisterModule((*MemoryUpstream)(nil))
}

type Traffic struct {
	Up   int64 `json:"up"`
	Down int64 `json:"down"`
}

type Upstream interface {
	Add(string) error
	Delete(string) error
	Range(func(string, int64, int64))
	Validate(string) bool
	Consume(string, int64, int64) error
}

type TaskType int

const (
	TaskAdd TaskType = iota
	TaskDelete
	TaskConsume
)

type Task struct {
	Type  TaskType
	Value struct {
		Password string
		Key      string
		Traffic
	}
}

type MemoryUpstream struct {
	UpstreamRaw json.RawMessage `json:"persist" caddy:"namespace=trojan.upstream inline_key=upstream"`

	ch chan Task
	up Upstream

	mu sync.RWMutex
	mm map[string]Traffic
}

func (*MemoryUpstream) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "trojan.upstream.memory",
		New: func() caddy.Module { return new(MemoryUpstream) },
	}
}

func (u *MemoryUpstream) Provision(ctx caddy.Context) error {
	u.mm = make(map[string]Traffic)

	if u.UpstreamRaw == nil {
		u.ch = make(chan Task)
		return nil
	}

	mod, err := ctx.LoadModule(u, "UpstreamRaw")
	if err != nil {
		return err
	}
	up := mod.(Upstream)

	up.Range(func(k string, nr, nw int64) {
		u.AddKey(k)
		u.Consume(k, nr, nw)
	})

	u.up = up
	u.ch = make(chan Task, 16)

	go func(up Upstream, ch chan Task) {
		for {
			t, ok := <-ch
			if !ok {
				break
			}
			switch t.Type {
			case TaskAdd:
				up.Add(t.Value.Password)
			case TaskDelete:
				up.Delete(t.Value.Password)
			case TaskConsume:
				up.Consume(t.Value.Key, t.Value.Up, t.Value.Down)
			default:
			}
		}
	}(u.up, u.ch)

	return nil
}

func (u *MemoryUpstream) Cleanup() error {
	if u.ch == nil {
		return nil
	}
	close(u.ch)
	return nil
}

func (u *MemoryUpstream) Add(s string) error {
	b := [trojan.HeaderLen]byte{}
	trojan.GenKey(s, b[:])

	u.AddKey(string(b[:]))

	if u.up == nil {
		return nil
	}

	t := Task{Type: TaskAdd}
	t.Value.Password = s
	u.ch <- t
	return nil
}

func (u *MemoryUpstream) AddKey(key string) {
	u.mu.Lock()
	u.mm[key] = Traffic{
		Up:   0,
		Down: 0,
	}
	u.mu.Unlock()
}

func (u *MemoryUpstream) Delete(s string) error {
	b := [trojan.HeaderLen]byte{}
	trojan.GenKey(s, b[:])
	key := x.ByteSliceToString(b[:])
	u.mu.Lock()
	delete(u.mm, key)
	u.mu.Unlock()

	if u.up == nil {
		return nil
	}

	t := Task{Type: TaskDelete}
	t.Value.Password = s
	u.ch <- t
	return nil
}

func (u *MemoryUpstream) Range(fn func(string, int64, int64)) {
	u.mu.RLock()
	for k, v := range u.mm {
		fn(k, v.Up, v.Down)
	}
	u.mu.RUnlock()
}

func (u *MemoryUpstream) Validate(k string) bool {
	u.mu.RLock()
	_, ok := u.mm[k]
	u.mu.RUnlock()
	return ok
}

func (u *MemoryUpstream) Consume(k string, nr, nw int64) error {
	u.mu.Lock()
	traffic := u.mm[k]
	traffic.Up += nr
	traffic.Down += nw
	u.mm[k] = traffic
	u.mu.Unlock()

	if u.up == nil {
		return nil
	}

	t := Task{Type: TaskConsume}
	t.Value.Key = k
	t.Value.Up = nr
	t.Value.Down = nw
	u.ch <- t
	return nil
}

type CaddyUpstream struct {
	prefix  string
	storage certmagic.Storage
	logger  *zap.Logger
}

func (CaddyUpstream) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "trojan.upstream.caddy",
		New: func() caddy.Module { return new(CaddyUpstream) },
	}
}

func (u *CaddyUpstream) Provision(ctx caddy.Context) error {
	u.prefix = "trojan/"
	u.storage = ctx.Storage()
	u.logger = ctx.Logger(u)
	return nil
}

func (u *CaddyUpstream) Add(s string) error {
	b := [trojan.HeaderLen]byte{}
	trojan.GenKey(s, b[:])
	key := u.prefix + string(b[:])
	if u.storage.Exists(context.Background(), key) {
		return nil
	}
	traffic := Traffic{
		Up:   0,
		Down: 0,
	}
	bb, err := json.Marshal(&traffic)
	if err != nil {
		return err
	}
	return u.storage.Store(context.Background(), key, bb)
}

func (u *CaddyUpstream) Delete(s string) error {
	b := [trojan.HeaderLen]byte{}
	trojan.GenKey(s, b[:])
	key := u.prefix + x.ByteSliceToString(b[:])
	if !u.storage.Exists(context.Background(), key) {
		return nil
	}
	return u.storage.Delete(context.Background(), key)
}

func (u *CaddyUpstream) Range(fn func(k string, up, down int64)) {
	prekeys, err := u.storage.List(context.Background(), u.prefix, false)
	if err != nil {
		return
	}

	traffic := Traffic{}
	for _, k := range prekeys {
		b, err := u.storage.Load(context.Background(), k)
		if err != nil {
			u.logger.Error(fmt.Sprintf("load user error: %v", err))
			continue
		}
		if err := json.Unmarshal(b, &traffic); err != nil {
			u.logger.Error(fmt.Sprintf("load user error: %v", err))
			continue
		}
		fn(strings.TrimPrefix(k, u.prefix), traffic.Up, traffic.Down)
	}
}

func (u *CaddyUpstream) Validate(k string) bool {
	key := u.prefix + k
	return u.storage.Exists(context.Background(), key)
}

func (u *CaddyUpstream) Consume(k string, nr, nw int64) error {
	key := u.prefix + k

	u.storage.Lock(context.Background(), key)
	defer u.storage.Unlock(context.Background(), key)

	b, err := u.storage.Load(context.Background(), key)
	if err != nil {
		return err
	}

	traffic := Traffic{}
	if err := json.Unmarshal(b, &traffic); err != nil {
		return err
	}

	traffic.Up += nr
	traffic.Down += nw

	b, err = json.Marshal(&traffic)
	if err != nil {
		return err
	}

	return u.storage.Store(context.Background(), key, b)
}

var (
	_ Upstream           = (*CaddyUpstream)(nil)
	_ Upstream           = (*MemoryUpstream)(nil)
	_ caddy.CleanerUpper = (*MemoryUpstream)(nil)
	_ caddy.Provisioner  = (*MemoryUpstream)(nil)
)
