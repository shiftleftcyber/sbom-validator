# ShiftSBOM Validator

[![Go Reference](https://pkg.go.dev/badge/github.com/shiftleftcyber/sbom-validator/v2.svg)](https://pkg.go.dev/github.com/shiftleftcyber/sbom-validator/v2)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Go Report Card](https://goreportcard.com/badge/github.com/shiftleftcyber/sbom-validator/v2)](https://goreportcard.com/report/github.com/shiftleftcyber/sbom-validator/v2)
![GitHub release (latest by date)](https://img.shields.io/github/v/release/shiftleftcyber/sbom-validator)

## Overview

**sbom-validator** is a Go library designed to validate
**Software Bill of Materials (SBOMs)** against the official
SBOM specifications. It ensures compliance with formats like
**CycloneDX**, **SPDX**, and **AI-SBOM** and helps maintain software supply chain security.

## Features

✅ Detects SBOM type (e.g., CycloneDX, SPDX, AI-SBOM)

✅ Extracts SBOM version

✅ Validates SBOM against official schemas

✅ Provides detailed validation errors

## Supported Formats

- CycloneDX JSON schemas: 1.2, 1.3, 1.4, 1.5, 1.6, 1.7
- SPDX JSON schemas: 2.2, 2.3
- AI-SBOM JSON schema: 1.0.0

The AI-SBOM schema is embedded from the immutable schema URL:

```text
https://shiftleftcyber.io/ai-bom/schemas/ai-sbom-1.0.0.schema.json
```

AI-SBOM author signatures are validated against the schema's JSF `signaturecore`
shape when `metadata.sbomAuthorSignature` is present.

## Installation

Use `go get` to install the package:

```sh
go get github.com/shiftleftcyber/sbom-validator/v2@latest
```

## Upgrading To v2

Existing projects pinned to older `v1` versions of `github.com/shiftleftcyber/sbom-validator`
will continue to work without changes.

To upgrade to `v2`, update your import path and dependency:

```sh
go get github.com/shiftleftcyber/sbom-validator/v2@latest
```

```go
import sbomvalidator "github.com/shiftleftcyber/sbom-validator/v2"
```

Projects still importing `github.com/shiftleftcyber/sbom-validator` without the `/v2`
suffix should remain on the `v1` line until they are ready to migrate.

## Usage

```go

package main

import (
    "encoding/json"
    "flag"
    "fmt"
    "log"
    "os"

    sbomvalidator "github.com/shiftleftcyber/sbom-validator/v2"
)

func main() {

    sbomPath := flag.String("file", "", "Path to the SBOM JSON file")
    debug := flag.Bool("debug", false, "Enable debug logging")
    flag.Parse()

    sbomvalidator.SetDebugLogging(*debug)

    // Ensure the file path is provided
    if *sbomPath == "" {
        log.Fatal("Usage: go run main.go -file=<path-to-sbom.json> [-debug]")
    }

    // Read SBOM file
    jsonData, err := os.ReadFile(*sbomPath)
    if err != nil {
        log.Fatalf("Failed to read SBOM file: %v", err)
    }

    result, err := sbomvalidator.ValidateSBOMData(jsonData)
    if err != nil {
        log.Fatalf("Error during validation - %v", err)
    }

    if result.IsValid {
        output, _ := json.MarshalIndent(result, "", " ")
        fmt.Println(string(output))
    } else {
        fmt.Printf("Validation failed! Showing up to %d errors:\n", 10)

        for i, errMsg := range result.ValidationErrors {
            if i >= 10 {
                fmt.Printf("...and %d more errors.\n", len(result.ValidationErrors)-10)
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

## Running the example

You can build an example app and pass in an SBOM

```sh
make build

./bin/sbom-validator-example -file sample-sboms/sample-1.6.cdx.json
{
 "isValid": true,
 "sbomType": "CycloneDX",
 "sbomVersion": "1.6",
 "detectedFormat": "JSON"
}

./bin/sbom-validator-example -file sample-sboms/sample-1.6.cdx.json -debug
DEBUG: 2026/04/07 14:00:00 CycloneDX SBOM type detected
DEBUG: 2026/04/07 14:00:00 CycloneDX version is set to: 1.6
{
 "isValid": true,
 "sbomType": "CycloneDX",
 "sbomVersion": "1.6",
 "detectedFormat": "JSON"
}

./bin/sbom-validator-example -file sample-sboms/customer-support-ai-sbom.json
{
 "isValid": true,
 "sbomType": "AI-SBOM",
 "sbomVersion": "1.0.0",
 "detectedFormat": "JSON"
}
```

AI-SBOM examples are included under `sample-sboms/`:

- `customer-support-ai-sbom.json`
- `medical-triage-ai-sbom.json`
- `missing-required-metadata.json`
- `bad-types-and-enums-ai-sbom.json`
- `non-jsf-signature-ai-sbom.json`
- `unknown-extra-properties-ai-sbom.json`

## License

This project is licensed under the MIT License.

## Contributing

Contributions are welcome! Please open an issue or submit a pull request.
