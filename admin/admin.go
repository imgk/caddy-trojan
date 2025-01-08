package admin

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"

	"github.com/caddyserver/caddy/v2"

	"github.com/imgk/caddy-trojan/app"
)

func init() {
	caddy.RegisterModule(Admin{})
}

// Admin is ...
type Admin struct {
	// Upstream is ...
	Upstream app.Upstream
}

// CaddyModule returns the Caddy module information.
func (Admin) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "admin.api.trojan",
		New: func() caddy.Module { return new(Admin) },
	}
}

// Provision is ...
func (al *Admin) Provision(ctx caddy.Context) error {
	ctx.App(app.CaddyAppID)
	if _, err := ctx.AppIfConfigured(app.CaddyAppID); err != nil {
		return nil
	}
	mod, err := ctx.App(app.CaddyAppID)
	if err != nil {
		return err
	}
	app := mod.(*app.App)
	al.Upstream = app.Upstream()
	return nil
}

// Routes returns a route for the /trojan/* endpoint.
func (al *Admin) Routes() []caddy.AdminRoute {
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
			Pattern: "/trojan/users/delete",
			Handler: caddy.AdminHandlerFunc(al.DeleteUser),
		},
	}
}

// GetUsers is ...
func (al *Admin) GetUsers(w http.ResponseWriter, r *http.Request) error {
	if al.Upstream == nil {
		return nil
	}

	if r.Method != http.MethodGet {
		return errors.New("get trojan user method error")
	}

	type User struct {
		Key  string `json:"key"`
		Up   int64  `json:"up"`
		Down int64  `json:"down"`
	}

	users := make([]User, 0)
	al.Upstream.Range(func(key string, up, down int64) {
		users = append(users, User{Key: key, Up: up, Down: down})
	})

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(users)
	return nil
}

// AddUser is ...
func (al *Admin) AddUser(w http.ResponseWriter, r *http.Request) error {
	if al.Upstream == nil {
		return nil
	}

	if r.Method != http.MethodPost {
		return errors.New("add trojan user method error")
	}

	type User struct {
		Password string `json:"password,omitempty"`
	}

	b, err := io.ReadAll(r.Body)
	if err != nil {
		return err
	}
	user := User{}
	if err := json.Unmarshal(b, &user); err != nil {
		return err
	}
	if user.Password != "" {
		al.Upstream.Add(user.Password)
	}

	w.WriteHeader(http.StatusOK)
	return nil
}

// DeleteUser is ...
func (al *Admin) DeleteUser(w http.ResponseWriter, r *http.Request) error {
	if al.Upstream == nil {
		return nil
	}

	if r.Method != http.MethodDelete {
		return errors.New("delete trojan user method error")
	}

	type User struct {
		Password string `json:"password,omitempty"`
	}

	b, err := io.ReadAll(r.Body)
	if err != nil {
		return err
	}
	user := User{}
	if err := json.Unmarshal(b, &user); err != nil {
		return err
	}
	if user.Password != "" {
		al.Upstream.Delete(user.Password)
	}

	w.WriteHeader(http.StatusOK)
	return nil
}

// Interface guards
var (
	_ caddy.AdminRouter = (*Admin)(nil)
	_ caddy.Provisioner = (*Admin)(nil)
)
