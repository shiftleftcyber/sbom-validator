package sbomvalidator

import (
	"embed"
	"encoding/json"
	"fmt"
	"log"

	"github.com/xeipuuv/gojsonschema"
)

const (
	SBOM_CYCLONEDX = "CycloneDX"
	SBOM_SPDX      = "SPDX"
)

// Embed all JSON schema files from the schemas/cyclonedx directory
//
//go:embed schemas/cyclonedx/*.json
var schemaFS embed.FS

// ValidateSBOMData is the main function to validate SBOM data using this library.
//
// This function serves as a wrapper around multiple internal functions, making it the
// recommended entry point for validating SBOMs. It performs the following steps:
// 1. Detects whether the SBOM is in JSON format.
// 2. Determines the SBOM type (CycloneDX, SPDX, etc.).
// 3. Extracts the schema version from the SBOM data.
// 4. Loads the corresponding schema for validation.
// 5. Validates the SBOM against the schema and returns the validation result.
//
// Parameters:
//   - sbomContent: A byte slice containing the SBOM data.
//
// Returns:
//   - bool: `true` if the SBOM is valid, `false` otherwise.
//   - []string: A list of validation error messages if the SBOM is invalid (nil if valid).
//   - error: An error if the function encounters issues during validation.
//
// Errors:
//   - Returns an error if the SBOM format is not JSON.
//   - Returns an error if SBOM type detection fails.
//   - Returns an error if the SBOM type is not CycloneDX (currently the only supported format).
//   - Returns an error if extracting the SBOM version fails.
//   - Returns an error if loading the schema fails.
//
// Note:
//   - This function abstracts multiple lower-level functions, such as `DetectSBOMType`,
//     `ExtractVersion`, `LoadSchema`, and `ValidateSBOM`. Instead of calling those
//     individually, use `ValidateSBOMData` for a streamlined validation process.
//
// Example usage:
//
//	isValid, errors, err := ValidateSBOMData(sbomBytes)
//	if err != nil {
//	    log.Fatalf("SBOM validation failed: %v", err)
//	}
//	if isValid {
//	    fmt.Println("SBOM is valid!")
//	} else {
//	    fmt.Println("SBOM validation errors:", errors)
//	}
func ValidateSBOMData(sbomContent []byte) (bool, []string, error) {
	if isJSON(sbomContent) {
		sbomType, err := detectSBOMType(string(sbomContent))
		if err != nil {
			return false, nil, fmt.Errorf("error detecting SBOM Type %s", err.Error())
		}

		if sbomType != SBOM_CYCLONEDX {
			return false, nil, fmt.Errorf("only CycloneDX is currenty supported")
		}

		sbomSchemaVersion, err := extractSBOMVersion(string(sbomContent), SBOM_CYCLONEDX)
		if err != nil {
			return false, nil, fmt.Errorf("failed to extract version: %v", err)
		}

		schema, err := loadSBOMSchema(sbomSchemaVersion, SBOM_CYCLONEDX)
		if err != nil {
			return false, nil, fmt.Errorf("failed to load schema: %v", err)
		}

		return validateSBOM(schema, string(sbomContent))

	} else {
		return false, nil, fmt.Errorf("unsupported file format")
	}
}

// detectSBOMType identifies the SBOM format based on the JSON structure.
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
//	sbomType, err := detectSBOMType(`{"bomFormat": "CycloneDX", "specVersion": "1.4"}`)
//	if err != nil {
//	    log.Fatalf("Failed to detect SBOM type: %v", err)
//	}
//	fmt.Println("Detected SBOM type:", sbomType) // Output: "CycloneDX"
func detectSBOMType(jsonData string) (string, error) {

	obj, err := ParseJSON(jsonData)
	if err != nil {
		return "", err
	}

	// CycloneDX contains a bomFormat field
	bomFormat, ok := obj["bomFormat"].(string)
	if ok {
		log.Println("CycloneDX SBOM type detected")
		return bomFormat, nil
	}

	spdxVersion, ok := obj["spdxVersion"].(string)
	if ok {
		return "", fmt.Errorf("SPDX is not currently supported - %v", spdxVersion)
	}

	return "", fmt.Errorf("unknown SBOM type or missing required fields")
}

// validateSBOM validates an SBOM JSON object against a provided SBOM schema.
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
//	valid, errors, err := validateSBOM(schemaJSON, sbomJSON)
//	if err != nil {
//	    log.Println("Validation error: %v", err)
//	}
//	if valid {
//	    fmt.Println("SBOM is valid!")
//	} else {
//	    fmt.Println("Validation failed with errors:")
//	    for _, e := range errors {
//	        fmt.Println("-", e)
//	    }
//	}
func validateSBOM(schemaSBOM, sbomData string) (bool, []string, error) {
	if !isValidJSON(sbomData) {
		return false, nil, fmt.Errorf("invalid JSON format")
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

// extractSBOMVersion extracts the "version" field from an SBOM JSON string.
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
//	version, err := extractSBOMVersion(`{"specVersion": "1.4"}`, "CycloneDX")
//	if err != nil {
//	    log.Println("Error extracting version: %v", err)
//	}
//	fmt.Println(version) // Output: "1.4"
func extractSBOMVersion(jsonData string, sbomType string) (string, error) {
	var obj map[string]interface{}

	if err := json.Unmarshal([]byte(jsonData), &obj); err != nil {
		return "", fmt.Errorf("invalid JSON format")
	}

	if sbomType == SBOM_CYCLONEDX {
		version, ok := obj["specVersion"].(string)
		if !ok {
			return "", fmt.Errorf(`"specVersion" field missing or not a string`)
		}

		log.Println("CycloneDX version is set to:", version)
		return version, nil
	} else if sbomType == SBOM_SPDX {
		version, ok := obj["spdxVersion"].(string)
		if !ok {
			return "", fmt.Errorf(`"spdxVersion" field missing or not a string`)
		}

		log.Println("SPDX version is set to:", version)
		return version, nil
	}

	return "", fmt.Errorf("unknown SBOM Format")
}

// loadSBOMSchema loads a JSON schema file for validating an SBOM.
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
//	schema, err := loadSBOMSchema("1.4", "schemas", SBOM_CYCLONEDX)
//	if err != nil {
//	    log.Fatalf("Failed to load schema: %v", err)
//	}
//	fmt.Println("Schema content loaded successfully.")
func loadSBOMSchema(version string, sbomType string) (string, error) {
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
