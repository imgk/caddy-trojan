// +build !malloc_cgo

package trojan

func malloc(n int) []byte {
	return make([]byte, n)
}

func free(b []byte) {}
