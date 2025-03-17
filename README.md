# Installer File Scraper

A tool for discovering, downloading, and indexing software installer files from websites. This scraper finds installer files (.exe, .msi, .dmg, .pkg, .deb, .rpm, etc.), computes their SHA3 hash, and stores metadata to a JSON file.

## Features

- Crawl websites for installer files with configurable depth
- Follow links within domains and subdomains
- Filter URLs using regular expressions
- Download files temporarily for processing
- Generate SHA3 hash for each installer
- Advanced file type detection with multiple detection methods
- Extract rich metadata including version, publisher, and signatures
- Detect file type and target platform with confidence scoring
- Store comprehensive metadata to JSON
- Deduplicate entries based on hash and URL
- Statistical analysis of collected installers
- Customizable concurrency settings
- Configurable request timeouts
- Clean up temporary files automatically
- Colored logging with configurable verbosity levels
- Performance timing measurements for components

## Installation

```bash
# Clone the repository
git clone https://github.com/deploymenttheory/go-app-index.git
cd go-app-index

# Build the application
go build -o installer-scraper ./cmd/installer-scraper
```

## Usage

```bash
# Basic usage
./installer-scraper -u https://example.com

# With custom depth and output file
./installer-scraper -u https://example.com -d 5 -o installers.json

# Filter URLs
./installer-scraper -u https://example.com -i "download|releases" -x "forum|blog"

# Control concurrency
./installer-scraper -u https://example.com -w 20 -W 10 -p 5

# Set request timeout (in seconds)
./installer-scraper -u https://example.com -t 600

# Enable verbose debug logging
./installer-scraper -u https://example.com -v

# Log to a file instead of stdout
./installer-scraper -u https://example.com --log-file=scraper.log
```

### Command Line Options

| Flag | Description | Default |
|------|-------------|---------|
| `-u, --url` | URL to start scraping (required) | - |
| `-o, --output` | Output JSON file | `installers.json` |
| `-d, --depth` | Maximum crawl depth | `3` |
| `-e, --extensions` | File extensions to look for | `.exe,.msi,.dmg,.pkg,.deb,.rpm,.AppImage` |
| `-i, --include` | Regex patterns to include URLs | - |
| `-x, --exclude` | Regex patterns to exclude URLs | - |
| `--temp-dir` | Temporary directory for downloads | System temp dir |
| `-w, --crawler-workers` | Number of crawler workers | `10` |
| `-W, --download-workers` | Number of download workers | `5` |
| `-p, --processor-workers` | Number of processor workers | `3` |
| `-D, --delay` | Delay between requests in milliseconds | `200` |
| `-t, --timeout` | HTTP request timeout in seconds. Default to 300 seconds (5 minutes if left unset) | `300` |
| `-c, --config` | Path to config file | - |
| `-v, --verbose` | Enable verbose debugging output | `false` |
| `--no-color` | Disable colored output | `false` |
| `--log-file` | Log to file instead of stdout | - |

## Example JSON Output

```json
{
  "last_updated": "2025-03-15T14:30:22Z",
  "stats": {
    "files_stored": 14,
    "unique_hashes": 14,
    "last_updated_at": "2025-03-15T14:30:22Z",
    "files_by_platform": {
      "windows": 8,
      "macos": 4,
      "linux": 2
    },
    "files_by_type": {
      "exe": 5,
      "msi": 3,
      "dmg": 3,
      "pkg": 1,
      "deb": 1,
      "rpm": 1
    },
    "avg_detection_score": 0.85,
    "signed_installer_count": 6,
    "versioned_file_count": 10
  },
  "timing": {
    "start_time": "2025-03-15T14:25:22Z",
    "end_time": "2025-03-15T14:30:22Z",
    "duration_ms": 300000,
    "crawler_time_ms": 280000,
    "downloader_time_ms": 250000,
    "processor_time_ms": 120000,
    "storage_time_ms": 5000
  },
  "installers": [
    {
      "filename": "application-1.2.3.dmg",
      "source_url": "https://example.com/downloads/application-1.2.3.dmg",
      "website_domain": "example.com",
      "discovered_at": "2025-03-15T12:45:22Z",
      "sha3_hash": "9a2f36c24cf75efdf2e7268f056827a0f416b351d827f3b536c71cac22ecd1b5",
      "file_size_bytes": 32485691,
      "platform": "macos",
      "file_type": "dmg",
      "detection_score": 0.92,
      "is_installer": true,
      "version": "1.2.3",
      "publisher": "Example Corp",
      "is_signed": true,
      "extended_metadata": {
        "has_resources": true,
        "compression": "zlib",
        "min_os_version": "10.12"
      }
    },
    {
      "filename": "application-setup-1.2.3.exe",
      "source_url": "https://example.com/downloads/application-setup-1.2.3.exe",
      "website_domain": "example.com",
      "discovered_at": "2025-03-15T12:45:18Z",
      "sha3_hash": "7d5e813f5c6b564506db7f97fc72aec2c3cecd991c7a4ddeeae5d31465de40b4",
      "file_size_bytes": 24680532,
      "platform": "windows",
      "file_type": "exe",
      "detection_score": 0.95,
      "is_installer": true,
      "version": "1.2.3",
      "publisher": "Example Corp",
      "is_signed": true,
      "extended_metadata": {
        "installer_type": "nsis",
        "bitness": "64-bit",
        "subsystem": "gui"
      }
    }
  ]
}
```

## Enhanced File Detection System

The application now includes an advanced file detection system that provides:

1. **Multi-layer detection**: Combines signature analysis, content inspection, and heuristics
2. **Platform identification**: Accurately determines target OS (Windows, macOS, Linux, etc.)
3. **Metadata extraction**: Pulls out version, publisher, and other installer details
4. **Digital signature verification**: Checks if installers are digitally signed
5. **Confidence scoring**: Provides reliability metrics for detection results

### Detection Methods

- **File Signatures**: Identifies file types by examining magic bytes/headers
- **Content Analysis**: Inspects binary contents for platform-specific patterns
- **Extension Validation**: Verifies file extensions match detected content type
- **Installer Heuristics**: Distinguishes installers from regular applications
- **Package Format Analysis**: Examines package structures (MSI, PKG, DEB, etc.)

### Metadata Extraction

The enhanced detection can extract:

- **Version information**: From binary resources, manifests, and filenames
- **Publisher details**: Company/developer name from signatures and resources
- **Platform requirements**: Target OS, architecture, minimum OS version
- **Installer type**: Setup engine used (NSIS, InstallShield, RPM, etc.)
- **Digital signatures**: Verification of file authenticity

### Statistics and Analytics

The application now collects and reports enhanced statistics:

- **Platform breakdown**: Counts of files by target platform
- **File type breakdown**: Counts of files by installer type
- **Detection confidence**: Average confidence score across all files
- **Signature analysis**: Count of signed vs. unsigned installers
- **Version extraction**: Success rate of version information extraction

## Logging

The application includes a comprehensive logging system with the following features:

- **Colored output**: Different colors for each log level (blue for INFO, yellow for WARNING, red for ERROR)
- **Configurable verbosity**: Control the amount of output with the `-v` flag
- **File logging**: Redirect logs to a file with `--log-file`
- **Disable colors**: Use `--no-color` when logging to files or terminals without color support

### Log Levels

- **ERROR**: Critical issues that prevent proper operation
- **WARNING**: Non-critical issues that may affect results
- **INFO**: Normal operational information
- **DEBUG**: Detailed information for troubleshooting (enabled with `-v`)

### Interpreting Logs

The default INFO level shows:
- URLs being visited
- Files being downloaded
- Processing status
- Final statistics
- Component timing information

The DEBUG level (with `-v`) additionally shows:
- All discovered links
- Link filtering decisions
- HTTP response details
- Detailed processing information
- File analysis confidence scores
- Metadata extraction results

## Performance Timing

The application now includes comprehensive timing measurements for each component:

- **Overall Duration**: Total execution time from start to finish
- **Crawler Time**: Time spent discovering URLs and links
- **Downloader Time**: Time spent downloading installer files
- **Processor Time**: Time spent processing files (hashing, metadata extraction)
- **Storage Time**: Time spent storing and writing metadata

This timing information is displayed in the logs at the end of execution and is also included in the JSON output.

## Use Cases

- Software catalog generation with rich metadata
- Vulnerability scanning of installer files
- Software update monitoring with version tracking
- Installer file verification with signature checking
- Software distribution platform scanning
- Performance benchmarking of software download servers
- Application intelligence gathering

## Performance Tuning

For optimal performance:

1. **URL filtering**: Use the `-i` and `-x` flags to focus crawling on productive paths
2. **Concurrency settings**: Adjust worker counts based on your network and system capabilities
3. **Crawl depth**: Limit depth to prevent excessive crawling
4. **Request delay**: Increase delay to be respectful to target websites
5. **Request timeout**: Adjust timeout for large files or slow networks

## Advanced Examples

### Targeting Download Sections

```bash
# Focus on download sections of a website
./installer-scraper -u https://example.com -i "download|files|releases" -x "forum|blog|account"
```

### Scanning Multiple Domains

```bash
# Create a script to scan multiple domains
for domain in example.com othersite.org thirdsite.net; do
  ./installer-scraper -u https://$domain -o ${domain}_installers.json
done
```

### High-Performance Configuration

```bash
# For fast networks and powerful systems
./installer-scraper -u https://example.com -w 30 -W 15 -p 8 -D 100
```

### Large File Downloads

```bash
# Extend timeout for sites with large installer files
./installer-scraper -u https://example.com -t 900 -W 3
```

### Detailed Debugging Session

```bash
# Maximum verbosity for troubleshooting
./installer-scraper -u https://example.com -v --log-file=debug.log
```

## Architecture

The application uses a hybrid pipeline/worker pool architecture:

1. **URL Crawler**: Discovers and filters URLs
2. **Downloader**: Detects and downloads installer files
3. **File Analyzer**: Advanced file type detection and metadata extraction
4. **Processor**: Generates hashes and processes files
5. **Storage**: Manages JSON output with deduplication and statistics
6. **Logger**: Provides structured, colored logging with configurable levels
7. **Timer**: Measures performance of each component

Each component uses worker pools with configurable concurrency.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License - see the LICENSE file for details.