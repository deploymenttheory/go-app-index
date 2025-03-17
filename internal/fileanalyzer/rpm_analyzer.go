package fileanalyzer

import (
	"crypto/sha256"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/cavaliergopher/rpm"
	"github.com/deploymenttheory/go-app-index/internal/logger"
)

// RPMAnalyzer analyzes RPM package files
type RPMAnalyzer struct{}

// CanHandle checks if the file is potentially an RPM package
func (a *RPMAnalyzer) CanHandle(filePath string, contentType string) bool {
	ext := strings.ToLower(filepath.Ext(filePath))
	if ext == ".rpm" {
		return true
	}

	if strings.Contains(strings.ToLower(contentType), "application/x-rpm") {
		return true
	}

	return false
}

// Analyze extracts information from an RPM package
func (a *RPMAnalyzer) Analyze(filePath string) (*Result, error) {
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

	// Try to read RPM headers
	pkg, err := rpm.Read(teeReader)
	if err != nil {
		logger.Debugf("Not a valid RPM file: %v", err)

		// Not a valid RPM - return low confidence result
		return &Result{
			FileType:    "unknown",
			Platform:    "unknown",
			Confidence:  0.1,
			IsInstaller: false,
			Metadata:    make(map[string]interface{}),
			AnalyzedAt:  time.Now(),
		}, nil
	}

	// Ensure the whole file is read to get the correct hash
	_, err = io.Copy(io.Discard, teeReader)
	if err != nil {
		logger.Warningf("Failed to read entire RPM file: %v", err)
		// Continue anyway, we might have enough information
	}

	// It's a valid RPM, so we have high confidence
	confidence := 0.9

	// Create installer metadata
	installerMeta := &InstallerMetadata{
		Name:       pkg.Name(),
		Version:    pkg.Version(),
		Publisher:  pkg.Vendor(),
		PackageIDs: []string{pkg.Name()},
		SHASum:     h.Sum(nil),
	}

	// Create main metadata map
	metadata := make(map[string]interface{})

	// Add installer metadata
	for k, v := range installerMeta.ToMap() {
		metadata[k] = v
	}

	// Add RPM-specific fields
	metadata["package_name"] = pkg.Name()
	metadata["package_version"] = pkg.Version()
	metadata["package_release"] = pkg.Release()
	metadata["package_epoch"] = pkg.Epoch()
	metadata["package_arch"] = pkg.Architecture()
	metadata["package_os"] = pkg.OperatingSystem()
	metadata["package_group"] = strings.Join(pkg.Groups(), ", ")
	metadata["package_sourcerpm"] = pkg.SourceRPM()
	metadata["url"] = pkg.URL()
	metadata["license"] = pkg.License()
	metadata["build_time"] = pkg.BuildTime()
	metadata["build_host"] = pkg.BuildHost()   // Add build host info
	metadata["vendor"] = pkg.Vendor()          // Explicit vendor extraction
	metadata["packager"] = pkg.Packager()      // Packager info
	metadata["rpm_version"] = pkg.RPMVersion() // Extract RPM version

	// Add package summary and description if available
	if pkg.Summary() != "" {
		metadata["summary"] = pkg.Summary()
	}
	if pkg.Description() != "" {
		metadata["description"] = pkg.Description()
	}

	logger.Debugf("RPM analysis of %s: name=%s, version=%s, license=%s",
		filePath, installerMeta.Name, installerMeta.Version, pkg.License())

	// Determine Linux distribution type if possible
	platform := "linux"
	switch strings.ToLower(pkg.Platform()) {
	case "redhat", "rhel":
		platform = "linux-rhel"
	case "suse":
		platform = "linux-suse"
	case "fedora":
		platform = "linux-fedora"
	case "centos":
		platform = "linux-centos"
	case "rocky":
		platform = "linux-rocky"
	case "alma":
		platform = "linux-almalinux"
	case "amazon":
		platform = "linux-amazon"
	}

	return &Result{
		FileType:    "rpm",
		Platform:    platform,
		Confidence:  confidence,
		IsInstaller: true,
		Metadata:    metadata,
		AnalyzedAt:  time.Now(),
	}, nil
}
