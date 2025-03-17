package fileanalyzer

import (
	"archive/tar"
	"bufio"
	"bytes"
	"compress/bzip2"
	"compress/gzip"
	"crypto/sha256"
	"errors"
	"io"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/blakesmith/ar"
	"github.com/deploymenttheory/go-app-index/internal/logger"
	"github.com/klauspost/compress/zstd"
	"github.com/xi2/xz"
)

// DEBAnalyzer analyzes Debian package files
type DEBAnalyzer struct{}

// CanHandle checks if the file is potentially a DEB package
func (a *DEBAnalyzer) CanHandle(filePath string, contentType string) bool {
	ext := strings.ToLower(filepath.Ext(filePath))
	if ext == ".deb" {
		return true
	}

	if strings.Contains(strings.ToLower(contentType), "application/vnd.debian.binary-package") ||
		strings.Contains(strings.ToLower(contentType), "application/x-debian-package") {
		return true
	}

	return false
}

// Analyze extracts information from a DEB package
func (a *DEBAnalyzer) Analyze(filePath string) (*Result, error) {
	// Open the file
	file, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	// Create a hash calculator
	h := sha256.New()

	// Create a reader that calculates hash while reading
	teeReader := io.TeeReader(file, h)

	// Try to validate as a DEB file
	arReader := ar.NewReader(teeReader)
	if arReader == nil {
		logger.Debugf("Not a valid DEB file: reader creation failed")

		// Not a valid DEB - return low confidence result
		return &Result{
			FileType:    "unknown",
			Platform:    "unknown",
			Confidence:  0.1,
			IsInstaller: false,
			Metadata:    make(map[string]interface{}),
			AnalyzedAt:  timeNow(),
		}, nil
	}

	// Look for control.tar file in the archive
	installerMeta, err := extractDebControlInfo(arReader)
	if err != nil {
		logger.Debugf("DEB control.tar extraction failed: %v", err)

		// It's still a DEB, even if we couldn't extract metadata
		return &Result{
			FileType:    "deb",
			Platform:    "linux-debian",
			Confidence:  0.8, // Lower confidence since we couldn't extract metadata
			IsInstaller: true,
			Metadata:    make(map[string]interface{}),
			AnalyzedAt:  timeNow(),
		}, nil
	}

	// Ensure the whole file is read to get the correct hash
	if _, err := io.Copy(io.Discard, teeReader); err != nil {
		logger.Warningf("Failed to read entire DEB file: %v", err)
		// Continue anyway, we might have enough information
	}

	// Add hash to installer metadata
	installerMeta.SHASum = h.Sum(nil)

	// Create main metadata map
	metadata := make(map[string]interface{})

	// Add installer metadata
	for k, v := range installerMeta.ToMap() {
		metadata[k] = v
	}

	logger.Debugf("DEB analysis of %s: name=%s, version=%s",
		filePath, installerMeta.Name, installerMeta.Version)

	// Add DEB-specific metadata
	metadata["package_name"] = installerMeta.Name

	// Determine more specific platform if possible
	platform := "linux-debian"

	return &Result{
		FileType:    "deb",
		Platform:    platform,
		Confidence:  0.9, // High confidence for DEB files
		IsInstaller: true,
		Metadata:    metadata,
		AnalyzedAt:  timeNow(),
	}, nil
}

// extractDebControlInfo extracts metadata from a DEB archive's control.tar file
func extractDebControlInfo(arReader *ar.Reader) (*InstallerMetadata, error) {
	for {
		header, err := arReader.Next()
		if err == io.EOF {
			break
		} else if err != nil {
			return nil, err
		}

		filename := path.Clean(header.Name)
		if strings.HasPrefix(filename, "control.tar") {
			ext := filepath.Ext(filename)
			if ext == ".tar" {
				ext = ""
			}

			name, version, err := parseDebControl(arReader, ext)
			if err != nil {
				return nil, err
			}

			return &InstallerMetadata{
				Name:       name,
				Version:    version,
				PackageIDs: []string{name},
			}, nil
		}
	}

	return nil, errors.New("no control.tar file found in DEB package")
}

// parseDebControl extracts the package name and version from the control file
func parseDebControl(r io.Reader, compressionExt string) (name, version string, err error) {
	var controlReader io.Reader = r

	// Handle different compression formats
	switch compressionExt {
	case ".gz":
		gz, err := gzip.NewReader(r)
		if err != nil {
			return "", "", err
		}
		defer gz.Close()
		controlReader = gz
	case ".bz2":
		controlReader = bzip2.NewReader(r)
	case ".xz":
		xzReader, err := xz.NewReader(r, 0)
		if err != nil {
			return "", "", err
		}
		controlReader = xzReader
	case ".zst":
		zstdReader, err := zstd.NewReader(r)
		if err != nil {
			return "", "", err
		}
		defer zstdReader.Close()
		controlReader = zstdReader
	case "":
		// Uncompressed, use reader as-is
	default:
		return "", "", errors.New("unsupported compression format in control.tar: " + compressionExt)
	}

	// Read the control archive as tar
	tarReader := tar.NewReader(controlReader)

	// Look for the 'control' file
	for {
		header, err := tarReader.Next()
		if err == io.EOF {
			break
		} else if err != nil {
			return "", "", err
		}

		if path.Clean(header.Name) == "control" {
			// Found the control file, read its contents
			controlContent, err := io.ReadAll(tarReader)
			if err != nil {
				return "", "", err
			}

			// Parse the control file for name and version
			scanner := bufio.NewScanner(bytes.NewReader(controlContent))
			for scanner.Scan() {
				line := scanner.Text()

				// Look for "Package:" and "Version:" lines
				if strings.HasPrefix(line, "Package:") {
					name = strings.TrimSpace(line[len("Package:"):])
				} else if strings.HasPrefix(line, "Version:") {
					version = strings.TrimSpace(line[len("Version:"):])
				}

				// If we found both name and version, we can stop
				if name != "" && version != "" {
					return name, version, nil
				}
			}

			// If we found the control file but not all fields, return what we have
			return name, version, nil
		}
	}

	return "", "", errors.New("control file not found in control.tar")
}
