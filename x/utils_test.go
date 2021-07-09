package x

import (
	"bytes"
	"testing"
)

func TestByteSliceToString(t *testing.T) {
	for _, v := range []string{
		"test1234",
	} {
		if ByteSliceToString([]byte(v)) != v {
			t.Errorf("convert error: %v", v)
		}
	}
}

func TestStringToByteSlice(t *testing.T) {
	for _, v := range []string{
		"test1234",
	} {
		if !bytes.Equal([]byte(v), StringToByteSlice(v)) {
			t.Errorf("convert error: %v", v)
		}
	}
}
