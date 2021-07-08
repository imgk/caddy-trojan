// +build malloc_cgo

package memory

// #include <stdlib.h>
import "C"

import "unsafe"

// Alloc is ...
func Alloc(n int) []byte {
	type SliceHeader struct {
		Data uintptr
		Len  int
		Cap  int
	}
	return *(*[]byte)(unsafe.Pointer(&SliceHeader{
		Data: uintptr(C.malloc(C.size_t(n))),
		Len:  n,
		Cap:  n,
	}))
}

// Free is ...
func Free(b []byte) {
	C.free(unsafe.Pointer(&b[0]))
}
