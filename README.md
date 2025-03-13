# ShiftSBOM Validator

[![Go Reference](https://pkg.go.dev/badge/github.com/shiftleftcyber/sbom-validator.svg)](https://pkg.go.dev/github.com/shiftleftcyber/sbom-validator)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Go Report Card](https://goreportcard.com/badge/github.com/shiftleftcyber/sbom-validator)](https://goreportcard.com/report/github.com/shiftleftcyber/sbom-validator)
![GitHub release (latest by date)](https://img.shields.io/github/v/release/shiftleftcyber/sbom-validator)


## Overview

**sbom-validator** is a Go library designed to validate
**Software Bill of Materials (SBOMs)** against the official
SBOM specifications. It ensures compliance with formats like
**CycloneDX** & **SPDX** and helps maintain software supply chain security.

## Features

✅ Detects SBOM type (e.g., CycloneDX, SPDX)

✅ Extracts SBOM version

✅ Validates SBOM against official schemas

✅ Provides detailed validation errors

## Installation

Use `go get` to install the package:

```sh
go get github.com/shiftleftcyber/sbom-validator
```

## Usage

```go

package main

import (
    "fmt"
    "log"
    "os"

    "github.com/shiftleftcyber/sbom-validator"
)

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
```

## Running Tests

```sh
go test ./...
```

or you can use the included Makefile

```sh
make test
```

## License

This project is licensed under the MIT License.

## Contributing

Contributions are welcome! Please open an issue or submit a pull request.
