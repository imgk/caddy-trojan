package utils

import "unsafe"

// ByteSliceToString is ...
func ByteSliceToString(b []byte) string {
	return *(*string)(unsafe.Pointer(&b))
}

// StringToByteSlice is ...
func StringToByteSlice(s string) []byte {
	ptr := (*struct {
		Data uintptr
		Len  int
	})(unsafe.Pointer(&s))
	return unsafe.Slice((*byte)(unsafe.Pointer(ptr.Data)), ptr.Len)
}
