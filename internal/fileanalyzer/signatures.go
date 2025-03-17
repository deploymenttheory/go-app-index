package fileanalyzer

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/deploymenttheory/go-app-index/internal/logger"
)

// FileSignature represents a file signature
type FileSignature struct {
	Name      string
	Magic     []byte
	Extension string
	Platform  string
	Type      string
}

// REF: https://en.wikipedia.org/wiki/List_of_file_signatures

// Updated file signatures from Wikipedia
var knownSignatures = []FileSignature{
	// Windows Executables
	{Name: "Windows Executable", Magic: []byte{0x4D, 0x5A}, Extension: ".exe", Platform: "windows", Type: "exe"},
	{Name: "Windows Installer", Magic: []byte{0xD0, 0xCF, 0x11, 0xE0}, Extension: ".msi", Platform: "windows", Type: "msi"},

	// macOS Installers
	{Name: "DMG Disk Image", Magic: []byte{0x78, 0x01, 0x73, 0x0D, 0x62, 0x62, 0x60}, Extension: ".dmg", Platform: "macos", Type: "dmg"},
	{Name: "PKG Installer", Magic: []byte{0x78, 0x61, 0x72, 0x21}, Extension: ".pkg", Platform: "macos", Type: "pkg"},

	// Linux Packages
	{Name: "Debian Package", Magic: []byte{0x21, 0x3C, 0x61, 0x72, 0x63, 0x68, 0x3E}, Extension: ".deb", Platform: "linux", Type: "deb"},
	{Name: "RPM Package", Magic: []byte{0xED, 0xAB, 0xEE, 0xDB}, Extension: ".rpm", Platform: "linux", Type: "rpm"},
	{Name: "AppImage", Magic: []byte{0x41, 0x49, 0x01}, Extension: ".AppImage", Platform: "linux", Type: "appimage"},

	// Java/Cross-platform
	{Name: "JAR File", Magic: []byte{0x50, 0x4B, 0x03, 0x04}, Extension: ".jar", Platform: "multiplatform", Type: "jar"},
	{Name: "ZIP Archive", Magic: []byte{0x50, 0x4B, 0x03, 0x04}, Extension: ".zip", Platform: "multiplatform", Type: "zip"},

	// Mobile Apps
	{Name: "APK File", Magic: []byte{0x50, 0x4B, 0x03, 0x04}, Extension: ".apk", Platform: "android", Type: "apk"},
	{Name: "IPA File", Magic: []byte{0x50, 0x4B, 0x03, 0x04}, Extension: ".ipa", Platform: "ios", Type: "ipa"},
}

// SignatureAnalyzer uses file signatures for detection
type SignatureAnalyzer struct{}

func (a *SignatureAnalyzer) CanHandle(filePath string, contentType string) bool {
	return true
}

// Analyze checks a file's signature against known patterns
func (a *SignatureAnalyzer) Analyze(filePath string) (*Result, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	header := make([]byte, 8)
	_, err = io.ReadAtLeast(file, header, len(header))
	if err != nil {
		return nil, err
	}

	for _, sig := range knownSignatures {
		if len(header) >= len(sig.Magic) && bytes.Equal(header[:len(sig.Magic)], sig.Magic) {
			logger.Debugf("Signature match: %s for file %s", sig.Name, filePath)
			ext := strings.ToLower(filepath.Ext(filePath))
			confidence := 0.7
			if ext == sig.Extension {
				confidence = 0.9
			}
			return &Result{
				FileType:    sig.Type,
				Platform:    sig.Platform,
				Confidence:  confidence,
				IsInstaller: isLikelyInstaller(sig.Type),
				Metadata: map[string]interface{}{
					"signature_name": sig.Name,
					"detected_by":    "signature",
				},
				AnalyzedAt: timeNow(),
			}, nil
		}
	}

	ext := strings.ToLower(filepath.Ext(filePath))
	for _, sig := range knownSignatures {
		if ext == sig.Extension {
			logger.Debugf("Extension match: %s for file %s", sig.Extension, filePath)
			return &Result{
				FileType:    sig.Type,
				Platform:    sig.Platform,
				Confidence:  0.5,
				IsInstaller: isLikelyInstaller(sig.Type),
				Metadata: map[string]interface{}{
					"detected_by": "extension",
				},
				AnalyzedAt: timeNow(),
			}, nil
		}
	}

	return &Result{
		FileType:    "unknown",
		Platform:    "unknown",
		Confidence:  0.1,
		IsInstaller: false,
		Metadata:    make(map[string]interface{}),
		AnalyzedAt:  timeNow(),
	}, nil
}

// isLikelyInstaller returns true if the file type is likely an installer
func isLikelyInstaller(fileType string) bool {
	installerTypes := map[string]bool{
		"msi":      true,
		"exe":      true,
		"dmg":      true,
		"pkg":      true,
		"deb":      true,
		"rpm":      true,
		"appimage": true,
	}
	return installerTypes[fileType]
}

var timeNow = func() time.Time {
	return time.Now()
}
