# ShiftSBOM Validator

[![Go Reference](https://pkg.go.dev/badge/github.com/shiftleftcyber/shiftsbom-validator.svg)](https://pkg.go.dev/github.com/yourusername/shiftsbom-validator)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

## Overview

**ShiftSBOM Validator** is a Go library designed to validate **Software Bill of Materials (SBOMs)** against the official SBOM specifications. It ensures compliance with formats like **CycloneDX** and helps maintain software supply chain security.

## Features

✅ Detects SBOM type (e.g., CycloneDX)  
✅ Extracts SBOM version  
✅ Validates SBOM JSON against official schemas  
✅ Provides detailed validation errors  

## Installation

Use `go get` to install the package:

```sh
go get github.com/shiftleftcyber/shiftsbom-validator
```

## Usage
```go
package main

import (
    "fmt"
    "log"
    "os"

    "github.com/shiftleftcyber/shiftsbom-validator"
)

func main() {
    sbomPath := "path/to/sbom.json"
    
    jsonData, err := os.ReadFile(sbomPath)
    if err != nil {
        log.Fatalf("Failed to read SBOM file: %v", err)
    }

    sbomType, err := sbomvalidator.DetectSBOMType(string(jsonData))
    if err != nil {
        log.Fatalf("Failed to detect SBOM type: %v", err)
    }

    version, err := sbomvalidator.ExtractVersion(string(jsonData), sbomType)
    if err != nil {
        log.Fatalf("Failed to extract SBOM version: %v", err)
    }

    schema, err := sbomvalidator.LoadSchema(version, "schemas", sbomType)
    if err != nil {
        log.Fatalf("Failed to load schema: %v", err)
    }

    valid, errors, err := sbomvalidator.ValidateSBOM(schema, string(jsonData))
    if err != nil {
        log.Fatalf("Validation error: %v", err)
    }

    if valid {
        fmt.Println("✅ SBOM is valid!")
    } else {
        fmt.Println("❌ SBOM validation failed:")
        for _, errMsg := range errors {
            fmt.Println("- " + errMsg)
        }
    }
}
```

## Running Tests

A convient Makefile is included. To run tests you can run

```sh
make test
```

## License

This project is licensed under the MIT License.

## Contributing

Contributions are welcome! Please open an issue or submit a pull request.