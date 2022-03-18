package memory

// Array is ...
type Array[T any] struct {
	data []T
}

// Slice is ...
func (arr *Array[T]) Slice() []T {
	return arr.data
}
