package trojan

import (
	"encoding/base64"
	"sync"
	"sync/atomic"

	"github.com/imgk/caddy-trojan/trojan"
	"github.com/imgk/caddy-trojan/utils"
)

// upstream is a global repository for saving all users
var upstream = NewUpstream()

type usage struct {
	up   int64
	down int64
}

// Upstream is ...
type Upstream struct {
	// RWMutex is ...
	sync.RWMutex
	// users is ...
	users map[string]struct{}
	// users usage
	usage struct {
		// RWMutex is ...
		sync.RWMutex
		// repo is ...
		repo map[string]usage
	}
	// total usage
	total usage
}

// NewUpstream is ...
func NewUpstream() *Upstream {
	up := &Upstream{}
	up.users = make(map[string]struct{})
	up.usage.repo = make(map[string]usage)
	return up
}

// AddKey is ...
func (u *Upstream) AddKey(k string) error {
	key := base64.StdEncoding.EncodeToString(utils.StringToByteSlice(k))
	u.Lock()
	u.users[key] = struct{}{}
	u.users[k] = struct{}{}
	u.Unlock()
	return nil
}

// Add is ...
func (u *Upstream) Add(s string) error {
	b := [trojan.HeaderLen]byte{}
	trojan.GenKey(s, b[:])
	u.AddKey(utils.ByteSliceToString(b[:]))
	return nil
}

// DelKey is ...
func (u *Upstream) DelKey(k string) error {
	key := base64.StdEncoding.EncodeToString(utils.StringToByteSlice(k))
	u.Lock()
	delete(u.users, key)
	delete(u.users, k)
	u.Unlock()

	u.usage.Lock()
	delete(u.usage.repo, key)
	delete(u.usage.repo, k)
	u.usage.Unlock()
	return nil
}

// Del is ...
func (u *Upstream) Del(s string) error {
	b := [trojan.HeaderLen]byte{}
	trojan.GenKey(s, b[:])
	u.DelKey(utils.ByteSliceToString(b[:]))
	return nil
}

// Range is ...
func (u *Upstream) Range(fn func(k string, up, down int64)) {
	// base64.StdEncoding.EncodeToString(hex.Encode(sha256.Sum224([]byte("Test1234"))))
	const AuthLen = 76

	u.RLock()
	for k := range u.users {
		if len(k) == AuthLen {
			continue
		}

		u.usage.RLock()
		v, ok := u.usage.repo[k]
		u.usage.RUnlock()
		if !ok {
			v = usage{}
		}

		k1 := base64.StdEncoding.EncodeToString(utils.StringToByteSlice(k))
		u.usage.RLock()
		v1, ok := u.usage.repo[k1]
		u.usage.RUnlock()
		if !ok {
			v1 = usage{}
		}

		fn(k, v.up+v1.up, v.down+v1.down)
	}
	u.RUnlock()
}

// Validate is ...
func (u *Upstream) Validate(s string) bool {
	u.RLock()
	_, ok := u.users[s]
	u.RUnlock()
	return ok
}

// Consume is ...
func (u *Upstream) Consume(s string, nr, nw int64) {
	u.usage.Lock()
	use, ok := u.usage.repo[s]
	if !ok {
		use = usage{}
	}
	use.up += nr
	use.down += nw
	u.usage.repo[s] = use
	u.usage.Unlock()

	atomic.AddInt64(&u.total.up, nr)
	atomic.AddInt64(&u.total.down, nw)
}
