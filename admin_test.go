package trojan

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/imgk/caddy-trojan/trojan"
	"github.com/imgk/caddy-trojan/x"
)

func TestGetUser(t *testing.T) {
	upstream.Add("test1234")

	req, err := http.NewRequest(http.MethodGet, "/trojan/users", nil)
	if err != nil {
		t.Fatal(err)
	}

	rr := httptest.NewRecorder()

	Admin{}.GetUsers(rr, req)

	if status := rr.Code; status != http.StatusOK {
		t.Errorf("handler returned wrong status code: got %v want %v", status, http.StatusOK)
	}

	b, err := io.ReadAll(rr.Body)
	if err != nil {
		t.Fatal(err)
	}

	type User struct {
		Key  string `json:"key"`
		Up   int64  `json:"up"`
		Down int64  `json:"down"`
	}
	user := []User{}
	if err := json.Unmarshal(b, &user); err != nil {
		t.Fatal(fmt.Errorf("%v error: %w", string(b), err))
	}

	if len(user) != 1 {
		t.Fatal(errors.New("user length error"))
	}

	buf := [trojan.HeaderLen]byte{}
	trojan.GenKey("test1234", buf[:])
	if user[0].Key != x.ByteSliceToString(buf[:]) {
		t.Fatal(errors.New("key error"))
	}
}

func TestAddUserAndDelUser(t *testing.T) {
	type User struct {
		Password string `json:"password,omitempty"`
		Key      string `json:"key,omitempty"`
	}
	user := User{Password: "imgk1234"}
	b, err := json.Marshal(&user)
	if err != nil {
		t.Errorf("marshal error: %v", err)
	}

	buf := [trojan.HeaderLen]byte{}
	trojan.GenKey("imgk1234", buf[:])

	req, err := http.NewRequest(http.MethodPost, "/trojan/users/add", bytes.NewReader(b))
	if err != nil {
		t.Fatal(err)
	}

	rr := httptest.NewRecorder()

	Admin{}.AddUser(rr, req)

	if status := rr.Code; status != http.StatusOK {
		t.Errorf("handler returned wrong status code: got %v want %v", status, http.StatusOK)
	}

	if _, ok := upstream.users[x.ByteSliceToString(buf[:])]; !ok {
		t.Errorf("add new user error")
	}

	req, err = http.NewRequest(http.MethodDelete, "/trojan/users/del", bytes.NewReader(b))
	if err != nil {
		t.Fatal(err)
	}

	rr = httptest.NewRecorder()

	Admin{}.DelUser(rr, req)

	if status := rr.Code; status != http.StatusOK {
		t.Errorf("handler returned wrong status code: got %v want %v", status, http.StatusOK)
	}

	if _, ok := upstream.users[x.ByteSliceToString(buf[:])]; ok {
		t.Errorf("del new user error")
	}
}
