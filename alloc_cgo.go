// +build malloc_cgo

package trojan

// #include <stdlib.h>
import "C"

import "unsafe"

func malloc(n int) []byte {
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

func free(b []byte) {
	C.free(unsafe.Pointer(&b[0]))
}
