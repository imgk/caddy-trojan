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
	return unsafe.Slice((*byte)(unsafe.Pointer(ptr.Data)), ptr.Len)
}
