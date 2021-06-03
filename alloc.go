// +build !malloc_cgo

package trojan

func alloc(n int) []byte {
	return make([]byte, n, n)
}

func free(b []byte) {}
