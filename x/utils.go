package x

import (
	"reflect"
	"unsafe"
)

// ByteSliceToString is ...
func ByteSliceToString(b []byte) string {
	return *(*string)(unsafe.Pointer(&b))
}

// StringToByteSlice is ...
func StringToByteSlice(s string) []byte {
	ptr := (*reflect.StringHeader)(unsafe.Pointer(&s))
	hdr := struct {
		Data uintptr
		Len  int
		Cap  int
	}{
		Data: ptr.Data,
		Len:  ptr.Len,
		Cap:  ptr.Len,
	}
	return *(*[]byte)(unsafe.Pointer(&hdr))
}
