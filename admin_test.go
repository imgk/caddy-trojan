package trojan

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestAdmin(t *testing.T) {
	upstream.Add("test1234")

	req, err := http.NewRequest("GET", "/trojan/users", nil)
	if err != nil {
		t.Fatal(err)
	}

	rr := httptest.NewRecorder()

	Admin{}.GetUsers(rr, req)

	if status := rr.Code; status != http.StatusOK {
		t.Errorf("handler returned wrong status code: got %v want %v",
			status, http.StatusOK)
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

	buf := [HeaderLen]byte{}
	GenKey("test1234", buf[:])
	if user[0].Key != ByteSliceToString(buf[:]) {
		t.Fatal(errors.New("key error"))
	}
}
