# Installer File Scraper

A tool for discovering, downloading, and indexing software installer files from websites. This scraper finds installer files (.exe, .msi, .dmg, .pkg, .deb, .rpm, etc.), computes their SHA3 hash, and stores metadata to a JSON file.

## Features

- Crawl websites for installer files with configurable depth
- Follow links within domains and subdomains
- Filter URLs using regular expressions
- Download files temporarily for processing
- Generate SHA3 hash for each installer
- Detect file type and target platform
- Store comprehensive metadata to JSON
- Deduplicate entries based on hash and URL
- Customizable concurrency settings
- Clean up temporary files automatically
- Colored logging with configurable verbosity levels

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
| `-c, --config` | Path to config file | - |
| `-v, --verbose` | Enable verbose debugging output | `false` |
| `--no-color` | Disable colored output | `false` |
| `--log-file` | Log to file instead of stdout | - |

## Example JSON Output

```json
{
  "last_updated": "2025-03-15T14:30:22Z",
  "stats": {
    "FilesStored": 14,
    "UniqueHashes": 14,
    "LastUpdatedAt": "2025-03-15T14:30:22Z"
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
      "file_type": "dmg"
    },
    {
      "filename": "application-setup-1.2.3.exe",
      "source_url": "https://example.com/downloads/application-setup-1.2.3.exe",
      "website_domain": "example.com",
      "discovered_at": "2025-03-15T12:45:18Z",
      "sha3_hash": "7d5e813f5c6b564506db7f97fc72aec2c3cecd991c7a4ddeeae5d31465de40b4",
      "file_size_bytes": 24680532,
      "platform": "windows",
      "file_type": "exe"
    }
  ]
}
```

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

The DEBUG level (with `-v`) additionally shows:
- All discovered links
- Link filtering decisions
- HTTP response details
- Detailed processing information

## Use Cases

- Software catalog generation
- Vulnerability scanning of installer files
- Software update monitoring
- Installer file verification
- Software distribution platform scanning

## Performance Tuning

For optimal performance:

1. **URL filtering**: Use the `-i` and `-x` flags to focus crawling on productive paths
2. **Concurrency settings**: Adjust worker counts based on your network and system capabilities
3. **Crawl depth**: Limit depth to prevent excessive crawling
4. **Request delay**: Increase delay to be respectful to target websites

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

### Detailed Debugging Session

```bash
# Maximum verbosity for troubleshooting
./installer-scraper -u https://example.com -v --log-file=debug.log
```

## Architecture

The application uses a hybrid pipeline/worker pool architecture:

1. **URL Crawler**: Discovers and filters URLs
2. **Downloader**: Detects and downloads installer files
3. **Processor**: Generates hashes and extracts metadata
4. **Storage**: Manages JSON output with deduplication
5. **Logger**: Provides structured, colored logging with configurable levels

Each component uses worker pools with configurable concurrency.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License - see the LICENSE file for details.