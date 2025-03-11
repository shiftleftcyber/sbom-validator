package sbomvalidator

import (
	"testing"
)

func TestIsJSON(t *testing.T) {
	tests := []struct {
		name      string
		jsonData  string
		want      bool
	}{
		{
			name:     "Valid JSON",
			jsonData: `{"bomFormat": "CycloneDX", "specVersion": "1.4"}`,
			want:     true,
		},
		{
			name: 		"Empty JSON",
			jsonData: 	`{}`,
			want: 		true,
		},
		{
			name: 		"Invalid JSON",
			jsonData: 	`{"bomFormat": "CycloneDX", "specVersion": 1.4`,
			want: 		false,
		},
		{
			name:      	"Completely empty string",
			jsonData:  	``,
			want: 		false,
		},
		{
			name:      	"Valid XML",
			jsonData: `<bom><bomFormat>CycloneDX</bomFormat><specVersion>1.4</specVersion></bom>`,
			want: 		false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isJSON([]byte(tt.jsonData))
			if got != tt.want {
				t.Errorf("isJSON() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestParseJSON(t *testing.T) {
	tests := []struct {
		name     string
		jsonData string
		want     bool
	}{
		{
			name:     "Valid JSON",
			jsonData: `{"bomFormat": "CycloneDX", "specVersion": "1.4"}`,
			want:     true,
		},
		{
			name:     "Empty JSON",
			jsonData: `{}`,
			want:     true,
		},
		{
			name:     "Invalid JSON",
			jsonData: `{"bomFormat": "CycloneDX", "specVersion": 1.4`,
			want:     false,
		},
		{
			name:     "Completely empty string",
			jsonData: ``,
			want:     false,
		},
		{
			name:     "Valid XML",
			jsonData: `<bom><bomFormat>CycloneDX</bomFormat><specVersion>1.4</specVersion></bom>`,
			want:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ParseJSON(tt.jsonData)
			got := err == nil // If err is nil, it means parsing was successful (valid JSON)
			if got != tt.want {
				t.Errorf("ParseJSON() for %s = %v, want %v", tt.name, got, tt.want)
			}
		})
	}
}