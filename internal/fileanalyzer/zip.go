package fileanalyzer

import (
	"archive/zip"
	"crypto/sha256"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/deploymenttheory/go-app-index/internal/logger"
)

// ZipAnalyzer analyzes ZIP-based package files
type ZipAnalyzer struct{}

// CanHandle checks if the file is a ZIP archive
func (a *ZipAnalyzer) CanHandle(filePath string, contentType string) bool {
	ext := strings.ToLower(filepath.Ext(filePath))
	return ext == ".zip" ||
		strings.Contains(strings.ToLower(contentType), "application/zip")
}

// Analyze extracts information from a ZIP package and determines if it contains an installer
func (a *ZipAnalyzer) Analyze(filePath string) (*Result, error) {
	metadata := make(map[string]interface{})

	// Compute SHA-256 hash
	shaSum, err := computeSHA256(filePath)
	if err != nil {
		return nil, err
	}
	metadata["sha256"] = shaSum

	// Scan for potential installer files
	containsInstaller, installerFiles := scanForInstallers(filePath)
	metadata["contains_installer"] = containsInstaller
	metadata["installer_files"] = installerFiles

	// If an installer is found, delegate to the appropriate analyzer
	if containsInstaller {
		bestInstaller := installerFiles[0] // Pick the first installer found
		logger.Infof("Delegating to installer analyzer for %s", bestInstaller)
		return delegateToInstallerAnalyzer(bestInstaller)
	}

	return &Result{
		FileType:    "zip",
		Platform:    "unknown",
		Confidence:  0.7,
		IsInstaller: false,
		Metadata:    metadata,
		AnalyzedAt:  timeNow(),
	}, nil
}

// computeSHA256 calculates the SHA-256 hash of a file
func computeSHA256(filePath string) (string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return "", err
	}
	defer file.Close()

	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return "", err
	}

	return string(hash.Sum(nil)), nil
}

// scanForInstallers checks for known installer formats inside the ZIP
func scanForInstallers(zipPath string) (bool, []string) {
	reader, err := zip.OpenReader(zipPath)
	if err != nil {
		logger.Errorf("Failed to open ZIP: %v", err)
		return false, nil
	}
	defer reader.Close()

	var installerFiles []string
	installerExtensions := []string{".exe", ".msi", ".pkg", ".dmg", ".appimage", ".deb", ".rpm"}

	for _, file := range reader.File {
		if file.FileInfo().IsDir() {
			continue
		}
		for _, ext := range installerExtensions {
			if strings.HasSuffix(strings.ToLower(file.Name), ext) {
				installerFiles = append(installerFiles, file.Name)
				break
			}
		}
	}

	return len(installerFiles) > 0, installerFiles
}

// delegateToInstallerAnalyzer determines the correct analyzer for an installer
func delegateToInstallerAnalyzer(installerPath string) (*Result, error) {
	if strings.HasSuffix(installerPath, ".msi") {
		analyzer := MSIAnalyzer{}
		return analyzer.Analyze(installerPath)
	}
	if strings.HasSuffix(installerPath, ".exe") {
		analyzer := PEAnalyzer{}
		return analyzer.Analyze(installerPath)
	}
	// Add support for other formats if needed
	return &Result{
		FileType:    "installer",
		Platform:    "unknown",
		Confidence:  0.9,
		IsInstaller: true,
		Metadata:    map[string]interface{}{"original_file": installerPath},
		AnalyzedAt:  timeNow(),
	}, nil
}
