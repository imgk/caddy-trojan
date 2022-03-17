package memory

import "testing"

func TestAlloc(t *testing.T) {
	if b := Alloc((*byte)(nil), 1024); len(b) != 1024 {
		t.Errorf("make slice error")
	}
}
