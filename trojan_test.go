package trojan

import "testing"

func TestByteSliceToString(t *testing.T) {
	for _, v := range []string{
		"test1234",
	} {
		if ByteSliceToString([]byte(v)) != v {
			t.Errorf("convert error: %v", v)
		}
	}
}

func Equal(x, y []byte) bool {
	if len(x) != len(y) {
		return false
	}
	if ByteSliceToString(x) != ByteSliceToString(y) {
		return false
	}
	return true
}

func TestStringToByteSlice(t *testing.T) {
	for _, v := range []string{
		"test1234",
	} {
		if !Equal([]byte(v), StringToByteSlice(v)) {
			t.Errorf("convert error: %v", v)
		}
	}
}
