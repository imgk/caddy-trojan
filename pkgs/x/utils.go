package x

import (
	"unsafe"
)

// ByteSliceToString is ...
func ByteSliceToString(b []byte) string {
	return *(*string)(unsafe.Pointer(&b))
}

// StringToByteSlice is ...
func StringToByteSlice(s string) []byte {
	return unsafe.Slice((*byte)(unsafe.Pointer(*(*uintptr)(unsafe.Pointer(&s)))), len(s))
}
