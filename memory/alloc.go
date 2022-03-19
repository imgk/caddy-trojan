package memory

// Array is ...
type Array[T any] struct {
	data []T
}

// Slice is ...
func (arr *Array[T]) Slice() []T {
	return arr.data
}

// Len is ...
func (arr *Array[T]) Len() int {
	return len(arr.data)
}
