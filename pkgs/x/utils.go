package x

import (
	"encoding/json"
	"reflect"
	"unsafe"
)

// ByteSliceToString is ...
func ByteSliceToString(b []byte) string {
	return *(*string)(unsafe.Pointer(&b))
}

// StringToByteSlice is ...
func StringToByteSlice(s string) []byte {
	return unsafe.Slice((*byte)(unsafe.Pointer(*(*uintptr)(unsafe.Pointer(&s)))), len(s))
}

// RemoveNullKeys removes keys with null values from a JSON object represented as a map[string]any.
func RemoveNullKeys(input map[string]any) map[string]any {
	out := make(map[string]any)
	for k, v := range input {
		if v != nil {
			if reflect.TypeOf(v).Kind() == reflect.Map {
				if subMap, ok := v.(map[string]any); ok {
					out[k] = RemoveNullKeys(subMap) // Recursively process nested maps
				} else {
					out[k] = v
				}
			} else {
				out[k] = v
			}
		}
	}
	return out
}

// RemoveNullKeysFromJSONString removes null keys from a JSON string.
func RemoveNullKeysFromJSONString(jsonString string) (string, error) {
	clearnedJSON, err := RemoveNullKeysFromJSON([]byte(jsonString))
	return string(clearnedJSON), err
}

// RemoveNullKeysFromJSON removes null keys from a JSON.RawMessage.
func RemoveNullKeysFromJSON(in json.RawMessage) (json.RawMessage, error) {
	var input map[string]any
	if err := json.Unmarshal(in, &input); err != nil {
		return nil, err
	}

	cleaned := RemoveNullKeys(input)

	cleanedJSON, err := json.Marshal(cleaned)
	if err != nil {
		return nil, err
	}

	return cleanedJSON, nil
}
