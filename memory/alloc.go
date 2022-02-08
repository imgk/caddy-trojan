// +build !malloc_cgo

package memory

import (
	"sync"
	"unsafe"
)

var buffer = &sync.Pool{
	New: newByteSlice,
}

func newByteSlice() interface{} {
	b := make([]byte, 16*1024)
	return &b[0]
}

// Alloc is ...
func Alloc(n int) []byte {
	if n > 16*1024 {
		return make([]byte, n)
	}
	ptr := buffer.Get().(*byte)
	return unsafe.Slice(ptr, n)
}

// Free is ...
func Free(b []byte) {
	if cap(b) == 16*1024 {
		buffer.Put(&b[0])
	}
}
