# Go DMG Handler

A native Go implementation for parsing, reading, and extracting Apple DMG (Disk Image) files.

## Features

- Pure Go implementation with no C/CGO dependencies
- Support for multiple compression methods (ZLIB, BZIP2, ADC, XZ)
- Efficient block caching system
- Full DMG header parsing
- File extraction
- Support for both XML and RSRC-based DMG files

## Installation

```bash
go get github.com/yourusername/dmg
```

## Usage

### Basic Usage

```go
package main

import (
    "fmt"
    "os"
    
    "github.com/yourusername/dmg"
)

func main() {
    // Open a DMG file
    handler, file, err := dmg.OpenFile("example.dmg")
    if err != nil {
        fmt.Fprintf(os.Stderr, "Error opening DMG: %v\n", err)
        os.Exit(1)
    }
    defer file.Close()
    defer handler.Close()
    
    // Print basic information
    fmt.Printf("DMG contains %d files\n", handler.GetNumberOfFiles())
    
    // Extract a file
    if handler.GetNumberOfFiles() > 0 {
        outFile, err := os.Create("extracted.img")
        if err != nil {
            fmt.Fprintf(os.Stderr, "Error creating output file: %v\n", err)
            os.Exit(1)
        }
        defer outFile.Close()
        
        if err := handler.ExtractFile(file, 0, outFile); err != nil {
            fmt.Fprintf(os.Stderr, "Error extracting file: %v\n", err)
            os.Exit(1)
        }
        
        fmt.Println("File extracted successfully")
    }
}
```

### Using the Command Line Tool

This package includes a command-line tool for working with DMG files.

1. Build the tool:

```bash
go build -o dmgtool cmd/dmgtool/main.go
```

2. List DMG contents:

```bash
./dmgtool -l example.dmg
```

3. Extract a specific file:

```bash
./dmgtool -e example.dmg 0 -o output_dir
```

4. Extract all files:

```bash
./dmgtool -x example.dmg -o output_dir
```

5. Show DMG information:

```bash
./dmgtool -i example.dmg
```

## Supported Compression Methods

- ZLIB (Method 0x80000005)
- BZIP2 (Method 0x80000006)
- ADC - Apple Data Compression (Method 0x80000004)
- XZ (Method 0x80000008)
- LZFSE (Method 0x80000007) - Note: Currently not implemented, will return an error

## Project Structure

- `block.go`: Block structures and methods
- `checksum.go`: Checksum handling
- `constants.go`: Constants and method types
- `decoder.go`: Compression decoders
- `dmg.go`: Package entry point
- `file.go`: File structures and methods
- `fork.go`: Fork pair handling
- `handler.go`: Main DMG handler
- `streams.go`: Stream implementations
- `utils.go`: Utility functions
- `xml.go`: XML parsing

## Limitations

- LZFSE compression is not currently implemented
- Some rare or legacy DMG formats may not be fully supported
- Very large DMG files might require significant memory for caching

## License

MIT License

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.