package sbomvalidator

import (
	"testing"
)

func TestIsJSON(t *testing.T) {
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
			_, err := parseJSON(tt.jsonData)
			got := err == nil // If err is nil, it means parsing was successful (valid JSON)
			if got != tt.want {
				t.Errorf("ParseJSON() for %s = %v, want %v", tt.name, got, tt.want)
			}
		})
	}
}

func TestGetSPDXVersion(t *testing.T) {
	tests := []struct {
		name         string
		spdxVersion  string
		expected     string
		expectError  bool
	}{
		{
			name:        "Valid SPDX version",
			spdxVersion: "SPDX-2.3",
			expected:    "2.3",
			expectError: false,
		},
		{
			name:        "Another valid SPDX version",
			spdxVersion: "SPDX-1.2",
			expected:    "1.2",
			expectError: false,
		},
		{
			name:        "Invalid format (missing version)",
			spdxVersion: "SPDX-",
			expected:    "",
			expectError: true,
		},
		{
			name:        "Invalid format (no hyphen)",
			spdxVersion: "SPDX",
			expected:    "",
			expectError: true,
		},
		{
			name:        "Empty string",
			spdxVersion: "",
			expected:    "",
			expectError: true,
		},
		{
			name:        "Extra hyphens but valid version",
			spdxVersion: "SPDX-2.3-extra",
			expected:    "2.3-extra", // Still valid, since we split only on the first hyphen
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := getSPDXVersion(tt.spdxVersion)
			if (err != nil) != tt.expectError {
				t.Errorf("getSPDXVersion(%q) error = %v, expected error = %v", tt.spdxVersion, err, tt.expectError)
			}
			if result != tt.expected {
				t.Errorf("getSPDXVersion(%q) = %q, want %q", tt.spdxVersion, result, tt.expected)
			}
		})
	}
}
