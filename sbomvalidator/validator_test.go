package sbomvalidator

import (
	"os"
	"path/filepath"
	"testing"
)

// TestDetectSBOMType tests the DetectSBOMType function.
func TestDetectSBOMType(t *testing.T) {
	tests := []struct {
		name      string
		jsonData  string
		want      string
		expectErr bool
	}{
		{
			name:     "Valid CycloneDX SBOM",
			jsonData: `{"bomFormat": "CycloneDX", "specVersion": "1.4"}`,
			want:     "CycloneDX",
		},
		{
			name:     "Valid SPDX SBOM",
			jsonData: `{"bomFormat": "SPDX", "spdxVersion": "2.2"}`,
			want:     "SPDX",
		},
		{
			name:      "Missing bomFormat field",
			jsonData:  `{"specVersion": "1.4"}`,
			expectErr: true,
		},
		{
			name:      "bomFormat field is not a string",
			jsonData:  `{"bomFormat": 123, "specVersion": "1.4"}`,
			expectErr: true,
		},
		{
			name:      "Invalid JSON format",
			jsonData:  `{"bomFormat": "CycloneDX", "specVersion": 1.4`,
			expectErr: true,
		},
		{
			name:      "Empty JSON",
			jsonData:  `{}`,
			expectErr: true,
		},
		{
			name:      "Completely empty string",
			jsonData:  ``,
			expectErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := DetectSBOMType(tt.jsonData)
			if (err != nil) != tt.expectErr {
				t.Errorf("DetectSBOMType() error = %v, expectErr %v", err, tt.expectErr)
				return
			}
			if got != tt.want && !tt.expectErr {
				t.Errorf("DetectSBOMType() = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestLoadSchema verifies that LoadSchema correctly loads schema files
// and handles errors properly.
func TestLoadSchema(t *testing.T) {
	// Create a temporary directory for schema files
	tempDir := t.TempDir()
	cdxSchemaDir := filepath.Join(tempDir, "cyclonedx")
	if err := os.MkdirAll(cdxSchemaDir, os.ModePerm); err != nil {
		t.Fatalf("Failed to create schema directory: %v", err)
	}

	// Define a valid test schema file
	validSchemaContent := `{"title": "CycloneDX Schema", "type": "object"}`
	version := "1.4"
	validSchemaPath := filepath.Join(cdxSchemaDir, "bom-1.4.schema.json")

	// Create a valid schema file
	if err := os.WriteFile(validSchemaPath, []byte(validSchemaContent), 0644); err != nil {
		t.Fatalf("Failed to write schema file: %v", err)
	}

	tests := []struct {
		name      string
		version   string
		schemaDir string
		sbomType  string
		wantErr   bool
		wantData  string
	}{
		{
			name:      "Valid CycloneDX Schema",
			version:   version,
			schemaDir: tempDir,
			sbomType:  SBOM_CYCLONEDX,
			wantErr:   false,
			wantData:  validSchemaContent,
		},
		{
			name:      "Schema File Not Found",
			version:   "2.0",
			schemaDir: tempDir,
			sbomType:  SBOM_CYCLONEDX,
			wantErr:   true,
		},
		{
			name:      "Unsupported SBOM Type",
			version:   version,
			schemaDir: tempDir,
			sbomType:  "UnknownSBOM",
			wantErr:   true,
		},
		{
			name:      "Invalid Schema Directory",
			version:   version,
			schemaDir: "/invalid/path",
			sbomType:  SBOM_CYCLONEDX,
			wantErr:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, err := LoadSchema(tt.version, tt.schemaDir, tt.sbomType)

			if tt.wantErr && err == nil {
				t.Errorf("Expected an error but got none")
			}

			if !tt.wantErr && err != nil {
				t.Errorf("Unexpected error: %v", err)
			}

			if !tt.wantErr && data != tt.wantData {
				t.Errorf("Schema content mismatch. Got: %v, Want: %v", data, tt.wantData)
			}
		})
	}
}

// TestExtractVersion verifies ExtractVersion correctly extracts SBOM versions
// and handles errors for invalid cases.
func TestExtractVersion(t *testing.T) {
	tests := []struct {
		name      string
		jsonData  string
		sbomType  string
		wantErr   bool
		wantValue string
	}{
		{
			name:      "Valid CycloneDX SBOM",
			jsonData:  `{"specVersion": "1.4"}`,
			sbomType:  "CycloneDX",
			wantErr:   false,
			wantValue: "1.4",
		},
		{
			name:     "Missing specVersion field",
			jsonData: `{"bomFormat": "CycloneDX"}`,
			sbomType: "CycloneDX",
			wantErr:  true,
		},
		{
			name:     "Invalid specVersion type",
			jsonData: `{"specVersion": 1.4}`,
			sbomType: "CycloneDX",
			wantErr:  true,
		},
		{
			name:     "Invalid JSON structure",
			jsonData: `{"specVersion": "1.4"`,
			sbomType: "CycloneDX",
			wantErr:  true,
		},
		{
			name:     "Unsupported SBOM type",
			jsonData: `{"specVersion": "1.4"}`,
			sbomType: "SPDX",
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			version, err := ExtractVersion(tt.jsonData, tt.sbomType)

			if tt.wantErr && err == nil {
				t.Errorf("Expected error but got none")
			}

			if !tt.wantErr && err != nil {
				t.Errorf("Unexpected error: %v", err)
			}

			if !tt.wantErr && version != tt.wantValue {
				t.Errorf("Expected version %q but got %q", tt.wantValue, version)
			}
		})
	}
}

// TestValidateSBOM verifies ValidateSBOM function for both valid and invalid SBOM data.
func TestValidateSBOM(t *testing.T) {
	validSchema := `{
		"$schema": "http://json-schema.org/draft-07/schema#",
		"type": "object",
		"properties": {
			"bomFormat": { "type": "string" },
			"specVersion": { "type": "string" }
		},
		"required": ["bomFormat", "specVersion"]
	}`

	tests := []struct {
		name       string
		schema     string
		sbomData   string
		wantValid  bool
		wantErrors bool
	}{
		{
			name:      "Valid SBOM",
			schema:    validSchema,
			sbomData:  `{"bomFormat": "CycloneDX", "specVersion": "1.4"}`,
			wantValid: true,
		},
		{
			name:       "Missing required field",
			schema:     validSchema,
			sbomData:   `{"bomFormat": "CycloneDX"}`, // Missing "specVersion"
			wantValid:  false,
			wantErrors: true,
		},
		{
			name:       "Invalid JSON format",
			schema:     validSchema,
			sbomData:   `{"bomFormat": "CycloneDX", "specVersion": 1.4}`, // specVersion should be string
			wantValid:  false,
			wantErrors: true,
		},
		{
			name:       "Empty JSON",
			schema:     validSchema,
			sbomData:   `{}`,
			wantValid:  false,
			wantErrors: true,
		},
		{
			name:       "Invalid Schema JSON",
			schema:     `{ "invalid": `, // Malformed schema
			sbomData:   `{"bomFormat": "CycloneDX", "specVersion": "1.4"}`,
			wantValid:  false,
			wantErrors: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			valid, errors, err := ValidateSBOM(tt.schema, tt.sbomData)

			if tt.wantValid && !valid {
				t.Errorf("Expected SBOM to be valid but got invalid")
			}

			if !tt.wantValid && valid {
				t.Errorf("Expected SBOM to be invalid but got valid")
			}

			if tt.wantErrors && len(errors) == 0 {
				t.Errorf("Expected validation errors but got none")
			}

			if !tt.wantErrors && len(errors) > 0 {
				t.Errorf("Expected no validation errors but got: %v", errors)
			}

			if err != nil && tt.name != "Invalid Schema JSON" {
				t.Errorf("Unexpected error: %v", err)
			}
		})
	}
}
