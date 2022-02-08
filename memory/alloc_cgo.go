// +build malloc_cgo

package memory

// #include <stdlib.h>
import "C"

import "unsafe"

// Alloc is ...
func Alloc(n int) []byte {
	return unsafe.Slice((*byte)(unsafe.Pointer(uintptr(C.malloc(C.size_t(n))))), n)
}

// Free is ...
func Free(b []byte) {
	C.free(unsafe.Pointer(&b[0]))
}
