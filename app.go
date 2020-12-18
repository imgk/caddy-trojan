package trojan

import (
	"net"
	"time"

	"github.com/go-redis/redis/v8"
	"go.uber.org/zap"
)

// App implements an caddy.App
type App struct {
	Users []string `json:"users,omitempty"`
	Redis struct {
		Addr     string `json:"addr"`
		Password string `json:"password"`
		DB       int    `json:"db"`
	} `json:"redis"`
	NICName   string `json:"nic_name,omitempty"`
	Allowance uint64 `json:"allowance,omitempty"`

	// logger
	logger *zap.Logger

	// users
	redis *redis.Client
	users map[string]struct{}

	// usage
	ticker *time.Ticker
	before uint64
	usage  uint64
}

// Provision implements caddy.Provisioner.
func (m *App) Provision(logger *zap.Logger) (err error) {
	m.logger = logger

	_, err = net.ResolveTCPAddr("tcp", m.Redis.Addr)
	if err != nil {
		return
	}
	m.redis = redis.NewClient(&redis.Options{
		Addr:     m.Redis.Addr,
		Password: m.Redis.Password,
		DB:       m.Redis.DB,
	})

	if m.NICName != "" {
		n1, n2, er := NetworkCard(m.NICName).GetUsage()
		if er != nil {
			err = er
			return
		}
		m.usage = 0
		m.before = n1 + n2
	}

	m.users = make(map[string]struct{})
	key := [HexLen]byte{}
	for _, user := range m.Users {
		GenKey(user, key[:])
		m.users[string(key[:HexLen])] = struct{}{}
	}

	return nil
}

// Start implements an caddy.App.Start
func (m *App) Start() error {
	if m.NICName != "" {
		m.ticker = time.NewTicker(time.Minute * 5)
		go m.renewUsage()
	}
	return nil
}

// Stop implements an caddy.App.Stop
func (m *App) Stop() error {
	if m.NICName != "" {
		m.ticker.Stop()
	}
	return nil
}
