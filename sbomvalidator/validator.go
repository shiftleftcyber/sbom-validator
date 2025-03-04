package sbomvalidator

import (
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"log"

	"github.com/xeipuuv/gojsonschema"
)

const (
	SBOM_CYCLONEDX = "CycloneDX"
	SBOM_SPDX      = "spdx"
)

// Embed all JSON schema files from the schemas/cyclonedx directory
//
//go:embed schemas/cyclonedx/*.json
var schemaFS embed.FS

// ValidateSBOM validates an SBOM JSON object against a provided SBOM schema.
//
// This function checks whether the given SBOM data conforms to the specified schema.
// Both the schema and the SBOM data should be provided as raw JSON strings.
//
// Parameters:
//   - schemaSBOM: A string containing the JSON schema for validation.
//   - sbomData: A string containing the SBOM JSON data to be validated.
//
// Returns:
//   - A boolean (`true` if validation passes, `false` otherwise).
//   - A slice of error messages if validation fails (nil if valid).
//   - An error if there is a problem with JSON parsing or schema processing.
//
// Example:
//
//	valid, errors, err := ValidateSBOM(schemaJSON, sbomJSON)
//	if err != nil {
//	    log.Fatalf("Validation error: %v", err)
//	}
//	if valid {
//	    fmt.Println("SBOM is valid!")
//	} else {
//	    fmt.Println("Validation failed with errors:")
//	    for _, e := range errors {
//	        fmt.Println("-", e)
//	    }
//	}
func ValidateSBOM(schemaSBOM, sbomData string) (bool, []string, error) {
	if !isValidJSON(sbomData) {
		return false, nil, errors.New("invalid JSON format")
	}

	schemaLoader := gojsonschema.NewStringLoader(schemaSBOM)
	documentLoader := gojsonschema.NewStringLoader(sbomData)

	_, err := gojsonschema.NewSchema(schemaLoader)
	if err != nil {
		return false, nil, fmt.Errorf("invalid schema format: %v", err)
	}

	result, err := gojsonschema.Validate(schemaLoader, documentLoader)
	if err != nil {
		return false, nil, err
	}

	if !result.Valid() {
		var errors []string
		for _, desc := range result.Errors() {
			errors = append(errors, desc.String())
		}
		return false, errors, nil
	}

	return true, nil, nil
}

// ExtractVersion extracts the "version" field from an SBOM JSON string.
//
// This function parses the provided JSON data and retrieves the version field
// based on the specified SBOM type. Currently, it supports CycloneDX SBOMs.
//
// Parameters:
//   - jsonData: A string containing the SBOM JSON data.
//   - sbomType: A string specifying the SBOM format (e.g., "CycloneDX").
//
// Returns:
//   - A string representing the SBOM version if found.
//   - An error if the JSON is invalid, the version field is missing, or the SBOM type is unsupported.
//
// Example:
//
//	version, err := ExtractVersion(`{"specVersion": "1.4"}`, "CycloneDX")
//	if err != nil {
//	    log.Fatalf("Error extracting version: %v", err)
//	}
//	fmt.Println(version) // Output: "1.4"
func ExtractVersion(jsonData string, sbomType string) (string, error) {
	var obj map[string]interface{}

	if err := json.Unmarshal([]byte(jsonData), &obj); err != nil {
		return "", errors.New("invalid JSON format")
	}

	if sbomType == "CycloneDX" {
		version, ok := obj["specVersion"].(string)
		if !ok {
			return "", errors.New(`"specVersion" field missing or not a string`)
		}

		log.Println("CycloneDX version is set to:", version)
		return version, nil
	}

	return "", errors.New("unknown SBOM Format")
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

// LoadSchema loads a JSON schema file for validating an SBOM.
//
// This function constructs the schema file path based on the SBOM version, schema directory,
// and SBOM type, then reads and returns the schema content.
//
// Parameters:
//   - version: The version of the SBOM schema (e.g., "1.4").
//   - schemaDir: The directory where schema files are stored.
//   - sbomType: The type of SBOM (currently supports "CycloneDX").
//
// Returns:
//   - A string containing the JSON schema content.
//   - An error if the schema file is missing, unreadable, or the SBOM type is unsupported.
//
// Example:
//
//	schema, err := LoadSchema("1.4", "schemas", SBOM_CYCLONEDX)
//	if err != nil {
//	    log.Fatalf("Failed to load schema: %v", err)
//	}
//	fmt.Println("Schema content loaded successfully.")
func LoadSchema(version string, sbomType string) (string, error) {
	if sbomType != SBOM_CYCLONEDX {
		return "", fmt.Errorf("unsupported SBOM type: %s", sbomType)
	}

	schemaFile := fmt.Sprintf("schemas/cyclonedx/bom-%s.schema.json", version)

	data, err := schemaFS.ReadFile(schemaFile)
	if err != nil {
		return "", fmt.Errorf("failed to read embedded schema file: %w", err)
	}

	return string(data), nil
}

// DetectSBOMType identifies the SBOM format based on the JSON structure.
//
// This function parses the provided SBOM JSON data and detects its type by checking the "bomFormat" field.
// It returns the detected SBOM type as a string (e.g., "CycloneDX").
//
// Parameters:
//   - jsonData: A string containing the SBOM JSON data.
//
// Returns:
//   - A string representing the detected SBOM format.
//   - An error if the JSON is invalid or the "bomFormat" field is missing.
//
// Example:
//
//	sbomType, err := DetectSBOMType(`{"bomFormat": "CycloneDX", "specVersion": "1.4"}`)
//	if err != nil {
//	    log.Fatalf("Failed to detect SBOM type: %v", err)
//	}
//	fmt.Println("Detected SBOM type:", sbomType) // Output: "CycloneDX"
func DetectSBOMType(jsonData string) (string, error) {

	var obj map[string]interface{}

	if err := json.Unmarshal([]byte(jsonData), &obj); err != nil {
		return "", errors.New("invalid JSON format")
	}

	bomFormat, ok := obj["bomFormat"].(string)
	if !ok {
		return "", errors.New(`"bomFormat" field missing or not a string`)
	}

	log.Println("SBOM type is:", bomFormat)
	return bomFormat, nil
}
