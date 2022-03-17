//go:build !malloc_cgo
// +build !malloc_cgo

package memory

// Alloc is ...
func Alloc[T any](_ *T, n int) Array[T] {
	return Array[T]{data: make([]T, n)}
}

// Free is ...
func Free[T any](_ Array[T]) {
	return
}
