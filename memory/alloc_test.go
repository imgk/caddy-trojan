package memory

import "testing"

func TestBuffer(t *testing.T) {
	_, ok := buffer.Get().(*byte)
	if !ok {
		t.Fatal("buffer type error")
	}
}
