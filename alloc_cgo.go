// +build malloc_cgo

package trojan

// #include <stdlib.h>
import "C"

import "unsafe"

type sliceHeader struct {
	Data uintptr
	Len  int
	Cap  int
}

func alloc(n int) []byte {
	return *(*[]byte)(unsafe.Pointer(&sliceHeader{
		Data: uintptr(C.malloc(C.ulong(n))),
		Len:  n,
		Cap:  n,
	}))
}

func free(b []byte) {
	C.free(unsafe.Pointer(&b[0]))
}
