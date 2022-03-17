package memory

// Array is ...
type Array[T any] struct {
	data []T
}

// Slice is ...
func (array Array[T]) Slice() []T {
	return array.data
}
