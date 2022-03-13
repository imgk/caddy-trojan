package trojan

import (
	"context"
	"encoding/base64"
	"encoding/json"

	"github.com/caddyserver/certmagic"

	"github.com/imgk/caddy-trojan/trojan"
	"github.com/imgk/caddy-trojan/utils"
)

// Traffic Usage
type TrafficUsage struct {
	// Up is ...
	Up int64 `json:"up"`
	// Down is ...
	Down int64 `json:"down"`
}

// Upstream is ...
type Upstream struct {
	// Prefix is ...
	Prefix string
	// Storage is ...
	certmagic.Storage
}

// NewUpstream is ...
func NewUpstream(st certmagic.Storage) Upstream {
	return Upstream{
		Prefix:  "trojan/",
		Storage: st,
	}
}

// AddKey is ...
func (u Upstream) AddKey(k string) error {
	key := u.Prefix + base64.StdEncoding.EncodeToString(utils.StringToByteSlice(k))
	if u.Exists(key) {
		return nil
	}
	traffic := TrafficUsage{
		Up:   0,
		Down: 0,
	}
	b, err := json.Marshal(&traffic)
	if err != nil {
		return err
	}
	return u.Store(key, b)
}

// Add is ...
func (u Upstream) Add(s string) error {
	b := [trojan.HeaderLen]byte{}
	trojan.GenKey(s, b[:])
	return u.AddKey(utils.ByteSliceToString(b[:]))
}

// DelKey is ...
func (u Upstream) DelKey(k string) error {
	key := u.Prefix + base64.StdEncoding.EncodeToString(utils.StringToByteSlice(k))
	if !u.Exists(key) {
		return nil
	}
	return u.Delete(key)
}

// Del is ...
func (u Upstream) Del(s string) error {
	b := [trojan.HeaderLen]byte{}
	trojan.GenKey(s, b[:])
	return u.DelKey(utils.ByteSliceToString(b[:]))
}

// Range is ...
func (u Upstream) Range(fn func(k string, up, down int64)) {
	// base64.StdEncoding.EncodeToString(hex.Encode(sha256.Sum224([]byte("Test1234"))))
	const AuthLen = 76

	keys, err := u.List(u.Prefix, false)
	if err != nil {
		return
	}

	traffic := TrafficUsage{}
	for _, k := range keys {
		b, err := u.Load(u.Prefix + k)
		if err != nil {
			continue
		}
		if err := json.Unmarshal(b, &traffic); err != nil {
			continue
		}
		fn(k, traffic.Up, traffic.Down)
	}

	return
}

// Validate is ...
func (u Upstream) Validate(k string) bool {
	// base64.StdEncoding.EncodeToString(hex.Encode(sha256.Sum224([]byte("Test1234"))))
	const AuthLen = 76
	if len(k) == AuthLen {
		k = u.Prefix + k
	} else {
		k = u.Prefix + base64.StdEncoding.EncodeToString(utils.StringToByteSlice(k))
	}
	return u.Exists(k)
}

// Consume is ...
func (u Upstream) Consume(k string, nr, nw int64) error {
	// base64.StdEncoding.EncodeToString(hex.Encode(sha256.Sum224([]byte("Test1234"))))
	const AuthLen = 76
	if len(k) == AuthLen {
		k = u.Prefix + k
	} else {
		k = u.Prefix + base64.StdEncoding.EncodeToString(utils.StringToByteSlice(k))
	}

	u.Lock(context.Background(), k)
	defer u.Unlock(k)

	b, err := u.Load(k)
	if err != nil {
		return err
	}

	traffic := TrafficUsage{}
	if err := json.Unmarshal(b, &traffic); err != nil {
		return err
	}

	traffic.Up += nr
	traffic.Down += nw

	b, err = json.Marshal(&traffic)
	if err != nil {
		return err
	}

	return u.Store(k, b)
}
