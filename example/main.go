package main

import (
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/shiftleftcyber/sbom-validator"
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

	isValid, validationErrors, err := sbomvalidator.ValidateSBOMData(jsonData)
	if err != nil {
		log.Fatalf("Error during validation - %v", err)
	}

	if isValid {
		fmt.Println("SBOM is valid")
	} else {
		fmt.Printf("Validation failed! Showing up to %d errors:\n", 10)

		for i, errMsg := range validationErrors {
			if i >= 10 {
				fmt.Printf("...and %d more errors.\n", len(validationErrors)-10)
				break
			}
			fmt.Printf("- %s\n", errMsg)
		}
	}
}
