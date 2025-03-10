package sbomvalidator

import (
	"encoding/json"
	"fmt"
)

func isJSON(data []byte) bool {
	var js json.RawMessage
	return json.Unmarshal(data, &js) == nil
}

func ParseJSON(jsonData string) (map[string]interface{}, error) {
	var obj map[string]interface{}
	if err := json.Unmarshal([]byte(jsonData), &obj); err != nil {
		return nil, fmt.Errorf("failed to parse JSON: %w", err)
	}

	return obj, nil
}
