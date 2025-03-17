package fileanalyzer

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/deploymenttheory/go-app-index/internal/logger"
)

// LinuxAnalyzer analyzes Linux installer files
type LinuxAnalyzer struct{}

// CanHandle checks if the file is a potential Linux package
func (a *LinuxAnalyzer) CanHandle(filePath string, contentType string) bool {
	ext := strings.ToLower(filepath.Ext(filePath))
	if ext == ".deb" || ext == ".rpm" || ext == ".appimage" ||
		strings.HasSuffix(strings.ToLower(filePath), ".tar.gz") {
		return true
	}

	if strings.Contains(strings.ToLower(contentType), "application/x-debian-package") ||
		strings.Contains(strings.ToLower(contentType), "application/x-rpm") ||
		strings.Contains(strings.ToLower(contentType), "application/x-executable") {
		return true
	}

	return false
}

// Analyze extracts information from a Linux package
func (a *LinuxAnalyzer) Analyze(filePath string) (*Result, error) {
	ext := strings.ToLower(filepath.Ext(filePath))
	lowerPath := strings.ToLower(filePath)

	metadata := make(map[string]interface{})
	var fileType string

	if ext == ".deb" || strings.Contains(lowerPath, ".deb") {
		fileType = "deb"
		debMetadata, err := analyzeDEB(filePath)
		if err == nil {
			for k, v := range debMetadata {
				metadata[k] = v
			}
		}
	} else if ext == ".rpm" || strings.Contains(lowerPath, ".rpm") {
		fileType = "rpm"
		rpmMetadata, err := analyzeRPM(filePath)
		if err == nil {
			for k, v := range rpmMetadata {
				metadata[k] = v
			}
		}
	} else if ext == ".appimage" || strings.Contains(lowerPath, ".appimage") {
		fileType = "appimage"
		appimageMetadata, err := analyzeAppImage(filePath)
		if err == nil {
			for k, v := range appimageMetadata {
				metadata[k] = v
			}
		}
	} else if strings.HasSuffix(lowerPath, ".tar.gz") || strings.HasSuffix(lowerPath, ".tgz") {
		fileType = "targz"
		targzMetadata, err := analyzeTarGz(filePath)
		if err == nil {
			for k, v := range targzMetadata {
				metadata[k] = v
			}
		}
	} else {
		// Default to generic Linux binary
		fileType = "binary"
		metadata["detected_by"] = "extension"
	}

	// Extract version info using generic string patterns
	version := extractLinuxVersion(filePath)
	if version != "" {
		metadata["version"] = version
	}

	// Overall result
	result := &Result{
		FileType:    fileType,
		Platform:    "linux",
		Confidence:  0.8,  // Good confidence for known extensions
		IsInstaller: true, // Assume all Linux packages are installers
		Metadata:    metadata,
		AnalyzedAt:  timeNow(),
	}

	logger.Debugf("Linux analysis of %s: type=%s", filePath, fileType)

	return result, nil
}

// analyzeDEB extracts information from a DEB package
func analyzeDEB(filePath string) (map[string]interface{}, error) {
	metadata := make(map[string]interface{})

	// Open the file
	file, err := os.Open(filePath)
	if err != nil {
		return metadata, err
	}
	defer file.Close()

	// Read the first 4KB to look for patterns
	buffer := make([]byte, 4096)
	_, err = file.Read(buffer)
	if err != nil {
		return metadata, err
	}

	// Look for the "debian-binary" marker
	if bytes.Contains(buffer, []byte("debian-binary")) {
		metadata["valid_deb"] = true
	}

	// Look for common field patterns in control file
	fields := map[string]string{
		"package":      `Package: ([^\n]+)`,
		"version":      `Version: ([^\n]+)`,
		"architecture": `Architecture: ([^\n]+)`,
		"maintainer":   `Maintainer: ([^\n]+)`,
		"description":  `Description: ([^\n]+)`,
	}

	// Convert buffer to string for regex
	bufferStr := string(buffer)

	for field, pattern := range fields {
		re := regexp.MustCompile(pattern)
		matches := re.FindStringSubmatch(bufferStr)
		if len(matches) > 1 {
			metadata[field] = strings.TrimSpace(matches[1])
		}
	}

	return metadata, nil
}

// analyzeRPM extracts information from an RPM package
func analyzeRPM(filePath string) (map[string]interface{}, error) {
	metadata := make(map[string]interface{})

	// Open the file
	file, err := os.Open(filePath)
	if err != nil {
		return metadata, err
	}
	defer file.Close()

	// Read the first 4KB
	buffer := make([]byte, 4096)
	_, err = file.Read(buffer)
	if err != nil {
		return metadata, err
	}

	// Check for the RPM lead magic number
	if len(buffer) >= 4 && buffer[0] == 0xED && buffer[1] == 0xAB &&
		buffer[2] == 0xEE && buffer[3] == 0xDB {
		metadata["valid_rpm"] = true
	}

	// Extract some info from the file using string patterns
	// This is a simplification; in a real implementation you'd use a proper RPM parsing library
	namePattern := regexp.MustCompile(`(?i)Name\s*:\s*([^\s]+)`)
	versionPattern := regexp.MustCompile(`(?i)Version\s*:\s*([^\s]+)`)
	releasePattern := regexp.MustCompile(`(?i)Release\s*:\s*([^\s]+)`)

	fileContent := string(buffer)

	if matches := namePattern.FindStringSubmatch(fileContent); len(matches) > 1 {
		metadata["package_name"] = matches[1]
	}

	if matches := versionPattern.FindStringSubmatch(fileContent); len(matches) > 1 {
		metadata["version"] = matches[1]
	}

	if matches := releasePattern.FindStringSubmatch(fileContent); len(matches) > 1 {
		metadata["release"] = matches[1]
	}

	return metadata, nil
}

// analyzeAppImage extracts information from an AppImage
func analyzeAppImage(filePath string) (map[string]interface{}, error) {
	metadata := make(map[string]interface{})

	// AppImages are ELF executables with specific sections
	file, err := os.Open(filePath)
	if err != nil {
		return metadata, err
	}
	defer file.Close()

	// Check if file starts with ELF magic number
	elfMagic := []byte{0x7F, 'E', 'L', 'F'}
	magic := make([]byte, 4)

	_, err = file.Read(magic)
	if err != nil {
		return metadata, err
	}

	if bytes.Equal(magic, elfMagic) {
		metadata["valid_elf"] = true

		// Check for AppImage signature in the first 32KB
		buffer := make([]byte, 32*1024)
		file.Seek(0, 0) // Go back to beginning
		_, err = file.Read(buffer)
		if err != nil && err != io.EOF {
			return metadata, err
		}

		if bytes.Contains(buffer, []byte("AppImage")) {
			metadata["valid_appimage"] = true
		}
	}

	return metadata, nil
}

// analyzeTarGz extracts information from a tar.gz archive
func analyzeTarGz(filePath string) (map[string]interface{}, error) {
	metadata := make(map[string]interface{})

	// Open the file
	file, err := os.Open(filePath)
	if err != nil {
		return metadata, err
	}
	defer file.Close()

	// Try to open as gzip file
	gzReader, err := gzip.NewReader(file)
	if err != nil {
		metadata["valid_gzip"] = false
		return metadata, err
	}
	defer gzReader.Close()

	metadata["valid_gzip"] = true

	// Try to read as tar archive
	tarReader := tar.NewReader(gzReader)
	fileCount := 0
	hasExecutable := false

	// Check first few entries to determine content
	for i := 0; i < 10; i++ {
		header, err := tarReader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			continue
		}

		fileCount++

		// Check for executable files
		if header.FileInfo().Mode()&0111 != 0 {
			hasExecutable = true
		}

		// Look for install scripts
		if strings.Contains(strings.ToLower(header.Name), "install") ||
			strings.Contains(strings.ToLower(header.Name), "setup") {
			metadata["has_install_script"] = true
		}
	}

	metadata["file_count"] = fileCount
	metadata["has_executable"] = hasExecutable

	// If it has executable files or install scripts, it's potentially an installer
	if hasExecutable || metadata["has_install_script"] == true {
		metadata["is_likely_installer"] = true
	}

	return metadata, nil
}

// extractLinuxVersion attempts to find version strings in the file
func extractLinuxVersion(filePath string) string {
	// Open the file
	file, err := os.Open(filePath)
	if err != nil {
		return ""
	}
	defer file.Close()

	// Read file in chunks to find version patterns
	buffer := make([]byte, 8192)
	for {
		n, err := file.Read(buffer)
		if err != nil && err != io.EOF {
			return ""
		}

		if n == 0 {
			break
		}

		// Common version patterns in Linux packages
		versionPatterns := []*regexp.Regexp{
			regexp.MustCompile(`(?i)version[\s="':]+([0-9]+\.[0-9]+(\.[0-9]+)?)`),
			regexp.MustCompile(`(?i)VERSION[\s="':]+([0-9]+\.[0-9]+(\.[0-9]+)?)`),
			regexp.MustCompile(`(?i)-([0-9]+\.[0-9]+(\.[0-9]+)?)-`),
			regexp.MustCompile(`(?i)_([0-9]+\.[0-9]+(\.[0-9]+)?)_`),
		}

		for _, pattern := range versionPatterns {
			matches := pattern.FindSubmatch(buffer[:n])
			if len(matches) > 1 {
				return string(matches[1])
			}
		}
	}

	return ""
}
