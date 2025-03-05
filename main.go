package main

import (
    "flag"
    "fmt"
    "log"
    "os"

    "github.com/shiftleftcyber/sbom-validator/sbomvalidator"
)

// main serves as a reference implementation for SBOM validation.
//
// This function demonstrates how to use the sbomvalidator package to:
//  1. Read an SBOM JSON file from a provided path.
//  2. Detect the SBOM type using the "bomFormat" field.
//  3. Extract the SBOM schema version.
//  4. Load the corresponding JSON schema.
//  5. Validate the SBOM JSON against the loaded schema.
//  6. Print validation results, limiting the number of reported errors.
//
// This implementation is primarily for demonstration purposes. Other projects
// can integrate the sbomvalidator package directly without using this main function.
//
// Usage:
//
//	go run main.go -file=<path-to-sbom.json>
//
// Example:
//
//	go run main.go -file=samples/juice-shop-17.1.1.cdx.json
func main() {

    sbomPath := flag.String("file", "", "Path to the SBOM JSON file")

    flag.Parse()

    // Ensure the file path is provided
    if *sbomPath == "" {
        log.Fatal("Usage: go run main.go -file=<path-to-sbom.json>")
    }

    // Read SBOM file
    jsonData, err := os.ReadFile(*sbomPath)
    if err != nil {
        log.Fatalf("Failed to read SBOM file: %v", err)
    }

    // Get SBOM Type
    sbomType, err := sbomvalidator.DetectSBOMType(string(jsonData))
    if err != nil {
        log.Fatalf("Failed to extract bomFormat: %v", err)
    }
    fmt.Println("Detected SBOM Type:", sbomType)

    // Extract version
    version, err := sbomvalidator.ExtractVersion(string(jsonData), sbomType)
    if err != nil {
        log.Fatalf("Failed to extract version: %v", err)
    }
    fmt.Println("Detected JSON Version:", version)

    // Load schema from schemas directory
    schema, err := sbomvalidator.LoadSchema(version, sbomType)
    if err != nil {
        log.Fatalf("Failed to load schema: %v", err)
    }

    // Validate JSON against the selected schema
    valid, errors, err := sbomvalidator.ValidateSBOM(schema, string(jsonData))
    if err != nil {
        log.Fatalf("Validation error: %v", err)
    }

    if valid {
        fmt.Println("JSON is valid!")
    } else {
        fmt.Printf("Validation failed! Showing up to %d errors:\n", 10)

        for i, errMsg := range errors {
            if i >= 10 {
                fmt.Printf("...and %d more errors.\n", len(errors)-10)
                break
            }
            fmt.Printf("- %s\n", errMsg)
        }
    }
}
