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

	"github.com/imgk/caddy-trojan/trojan"
	"github.com/imgk/caddy-trojan/utils"
)

func init() {
	caddy.RegisterModule(CaddyUpstream{})
	caddy.RegisterModule(MemoryUpstream{})
}

// Upstream is ...
type Upstream interface {
	// Add is ...
	Add(string) error
	// Delete is ...
	Delete(string) error
	// Range is ...
	Range(func(string, int64, int64))
	// Validate is ...
	Validate(string) bool
	// Consume is ...
	Consume(string, int64, int64) error
}

// TaskType is ...
type TaskType int

const (
	TaskAdd TaskType = iota
	TaskDelete
	TaskConsume
)

// Task is ...
type Task struct {
	Type  TaskType
	Value struct {
		Password string
		Key      string
		Traffic
	}
}

// MemoryUpstream is ...
type MemoryUpstream struct {
	// UpstreamRaw is ...
	UpstreamRaw json.RawMessage `json:"upstream" caddy:"namespace=trojan.upstreams inline_key=upstream"`

	ch chan Task
	up Upstream

	mu sync.RWMutex
	mm map[string]Traffic
}

// CaddyModule is ...
func (MemoryUpstream) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "trojan.upstreams.memory",
		New: func() caddy.Module { return new(MemoryUpstream) },
	}
}

// Provision is ...
func (u *MemoryUpstream) Provision(ctx caddy.Context) error {
	u.mm = make(map[string]Traffic)

	if u.UpstreamRaw == nil {
		return nil
	}

	mod, err := ctx.LoadModule(u, "UpstreamRaw")
	if err != nil {
		return err
	}
	up := mod.(Upstream)

	up.Range(func(k string, nr, nw int64) {
		u.Add(k)
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

// Cleanup is ...
func (u *MemoryUpstream) Cleanup() error {
	close(u.ch)
	return nil
}

// Add is ...
func (u *MemoryUpstream) Add(s string) error {
	b := [trojan.HeaderLen]byte{}
	trojan.GenKey(s, b[:])
	key := string(b[:])
	u.mu.Lock()
	u.mm[key] = Traffic{
		Up:   0,
		Down: 0,
	}
	u.mu.Unlock()

	if u.up == nil {
		return nil
	}

	t := Task{Type: TaskAdd}
	t.Value.Password = s
	u.ch <- t
	return nil
}

// Delete is ...
func (u *MemoryUpstream) Delete(s string) error {
	b := [trojan.HeaderLen]byte{}
	trojan.GenKey(s, b[:])
	key := utils.ByteSliceToString(b[:])
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

// Range is ...
func (u *MemoryUpstream) Range(fn func(string, int64, int64)) {
	u.mu.RLock()
	for k, v := range u.mm {
		fn(k, v.Up, v.Down)
	}
	u.mu.RUnlock()
}

// Validate is ...
func (u *MemoryUpstream) Validate(k string) bool {
	u.mu.RLock()
	_, ok := u.mm[k]
	u.mu.RUnlock()
	return ok
}

// Consume is ...
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

// CaddyUpstream is ...
type CaddyUpstream struct {
	// Prefix is ...
	Prefix string `json:"-,omitempty"`
	// Storage is ...
	Storage certmagic.Storage `json:"-,omitempty"`
	// Logger is ...
	Logger *zap.Logger `json:"-,omitempty"`
}

// CaddyModule is ...
func (CaddyUpstream) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "trojan.upstreams.caddy",
		New: func() caddy.Module { return new(CaddyUpstream) },
	}
}

// Provision is ...
func (u *CaddyUpstream) Provision(ctx caddy.Context) error {
	u.Prefix = "trojan/"
	u.Storage = ctx.Storage()
	u.Logger = ctx.Logger(u)
	return nil
}

// Add is ...
func (u *CaddyUpstream) Add(s string) error {
	b := [trojan.HeaderLen]byte{}
	trojan.GenKey(s, b[:])
	key := u.Prefix + string(b[:])
	if u.Storage.Exists(context.Background(), key) {
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
	return u.Storage.Store(context.Background(), key, bb)
}

// Delete is ...
func (u *CaddyUpstream) Delete(s string) error {
	b := [trojan.HeaderLen]byte{}
	trojan.GenKey(s, b[:])
	key := u.Prefix + utils.ByteSliceToString(b[:])
	if !u.Storage.Exists(context.Background(), key) {
		return nil
	}
	return u.Storage.Delete(context.Background(), key)
}

// Range is ...
func (u *CaddyUpstream) Range(fn func(k string, up, down int64)) {
	prekeys, err := u.Storage.List(context.Background(), u.Prefix, false)
	if err != nil {
		return
	}

	traffic := Traffic{}
	for _, k := range prekeys {
		b, err := u.Storage.Load(context.Background(), k)
		if err != nil {
			u.Logger.Error(fmt.Sprintf("load user error: %v", err))
			continue
		}
		if err := json.Unmarshal(b, &traffic); err != nil {
			u.Logger.Error(fmt.Sprintf("load user error: %v", err))
			continue
		}
		fn(strings.TrimPrefix(k, u.Prefix), traffic.Up, traffic.Down)
	}

	return
}

// Validate is ...
func (u *CaddyUpstream) Validate(k string) bool {
	key := u.Prefix + k
	return u.Storage.Exists(context.Background(), key)
}

// Consume is ...
func (u *CaddyUpstream) Consume(k string, nr, nw int64) error {
	key := u.Prefix + k

	u.Storage.Lock(context.Background(), key)
	defer u.Storage.Unlock(context.Background(), key)

	b, err := u.Storage.Load(context.Background(), key)
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

	return u.Storage.Store(context.Background(), key, b)
}

var (
	_ Upstream           = (*CaddyUpstream)(nil)
	_ Upstream           = (*MemoryUpstream)(nil)
	_ caddy.CleanerUpper = (*MemoryUpstream)(nil)
	_ caddy.Provisioner  = (*MemoryUpstream)(nil)
)
