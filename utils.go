package sbomvalidator

import (
	"encoding/json"
	"fmt"
)

func isJSON(data []byte) bool {
	var js json.RawMessage
	return json.Unmarshal(data, &js) == nil
}

func parseJSON(jsonData string) (map[string]interface{}, error) {
	var obj map[string]interface{}
	if err := json.Unmarshal([]byte(jsonData), &obj); err != nil {
		return nil, fmt.Errorf("failed to parse JSON: %w", err)
	}

	return obj, nil
}

// isValidJSON checks whether a given string contains valid JSON.
//
// It attempts to unmarshal the input string into a `json.RawMessage`
// to determine if it is well-formed JSON.
//
// Parameters:
//   - jsonStr: A string containing the JSON data to validate.
//
// Returns:
//   - A boolean value: `true` if the input is valid JSON, `false` otherwise.
//
// Example:
//
//	valid := isValidJSON(`{"name": "ShiftLeftCyber", "secure": true}`)
//	fmt.Println(valid) // Output: true
func isValidJSON(jsonStr string) bool {
	var js json.RawMessage
	return json.Unmarshal([]byte(jsonStr), &js) == nil
}
