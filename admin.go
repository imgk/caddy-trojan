package trojan

import (
	"encoding/json"
	"net/http"

	"github.com/caddyserver/caddy/v2"
)

func init() {
	caddy.RegisterModule(Admin{})
}

// Admin is ...
type Admin struct{}

// CaddyModule returns the Caddy module information.
func (Admin) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "admin.api.trojan",
		New: func() caddy.Module { return new(Admin) },
	}
}

// Routes returns a route for the /trojan/* endpoint.
func (al Admin) Routes() []caddy.AdminRoute {
	return []caddy.AdminRoute{
		{
			Pattern: "/trojan/users",
			Handler: caddy.AdminHandlerFunc(al.GetUsers),
		},
		{
			Pattern: "/trojan/users/add",
			Handler: caddy.AdminHandlerFunc(al.AddUser),
		},
		{
			Pattern: "/trojan/users/del",
			Handler: caddy.AdminHandlerFunc(al.DelUser),
		},
	}
}

// GetUsers is ...
func (Admin) GetUsers(w http.ResponseWriter, r *http.Request) error {
	type User struct {
		Key  string `json:"key"`
		Up   int64  `json:"up"`
		Down int64  `json:"down"`
	}

	users := make([]User, 0, len(upstream.users)/2)
	upstream.Range(func(k string, up, down int64) {
		users = append(users, User{Key: k, Up: up, Down: down})
	})

	json.NewEncoder(w).Encode(users)
	return nil
}

// AddUser is ...
func (Admin) AddUser(w http.ResponseWriter, r *http.Request) error {
	type User struct {
		Password string `json:"password"`
	}
	return nil
}

// DelUser is ...
func (Admin) DelUser(w http.ResponseWriter, r *http.Request) error {
	type User struct {
		Password string `json:"password"`
	}
	return nil
}
