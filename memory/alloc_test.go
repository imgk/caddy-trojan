package memory

import "testing"

func TestAlloc(t *testing.T) {
	if arr := Alloc((*byte)(nil), 1024); arr.Len() != 1024 {
		t.Errorf("make slice error")
	}
}
