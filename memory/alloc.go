// +build !malloc_cgo

package memory

import (
	"sync"
	"unsafe"
)

var buffer = &sync.Pool{
	New: func() interface{} {
		b := make([]byte, 16*1024)
		return &b[0]
	},
}

// Alloc is ...
func Alloc(n int) []byte {
	if n > 16*1024 {
		return make([]byte, n)
	}
	type SliceHeader struct {
		Data uintptr
		Len  int
		Cap  int
	}
	ptr := buffer.Get().(*byte)
	return *(*[]byte)(unsafe.Pointer(&SliceHeader{
		Data: uintptr(unsafe.Pointer(ptr)),
		Len:  n,
		Cap:  16 * 1024,
	}))
}

// Free is ...
func Free(b []byte) {
	if cap(b) == 16*1024 {
		buffer.Put(&b[0])
	}
}
