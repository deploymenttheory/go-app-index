package downloader

import (
	"mime"
	"path/filepath"
	"strings"

	"github.com/deploymenttheory/go-app-index/internal/fileanalyzer"
	"github.com/deploymenttheory/go-app-index/internal/logger"
)

// FileType represents a type of installer file
type FileType struct {
	Extensions []string
	MimeTypes  []string
	Platform   string
}

// Known installer file types
var knownFileTypes = []FileType{
	{
		Extensions: []string{".exe", ".msi"},
		MimeTypes:  []string{"application/x-msdownload", "application/x-msi", "application/octet-stream"},
		Platform:   "windows",
	},
	{
		Extensions: []string{".dmg", ".pkg"},
		MimeTypes:  []string{"application/x-apple-diskimage", "application/vnd.apple.installer+xml", "application/octet-stream"},
		Platform:   "macos",
	},
	{
		Extensions: []string{".deb", ".rpm", ".AppImage"},
		MimeTypes:  []string{"application/vnd.debian.binary-package", "application/x-rpm", "application/x-executable", "application/octet-stream"},
		Platform:   "linux",
	},
}

// DetectFileType detects the type of installer file based on name and content type
// If filePath is provided, enhanced analysis will be performed
func DetectFileType(fileName, contentType string, filePath string) (fileType, platform string, confidence float64) {
	// Try enhanced detection if file path is provided
	if filePath != "" {
		// Initialize analyzer manager
		analyzer := fileanalyzer.NewManager()

		// Perform analysis
		result, err := analyzer.Analyze(filePath, contentType)
		if err == nil && result.Confidence > 0.5 {
			logger.Debugf("Enhanced file detection result: %s, %s, confidence: %.2f",
				result.FileType, result.Platform, result.Confidence)

			return result.FileType, result.Platform, result.Confidence
		}
	}

	// Fall back to basic detection
	ext := strings.ToLower(filepath.Ext(fileName))
	lowerContentType := strings.ToLower(contentType)

	// Try to detect by extension first
	for _, ft := range knownFileTypes {
		for _, e := range ft.Extensions {
			if e == ext {
				return strings.TrimPrefix(ext, "."), ft.Platform, 0.7
			}
		}
	}

	// If extension check fails, try by MIME type
	for _, ft := range knownFileTypes {
		for _, mt := range ft.MimeTypes {
			if strings.Contains(lowerContentType, mt) {
				// Use extension if available, otherwise use generic name
				if ext != "" {
					return strings.TrimPrefix(ext, "."), ft.Platform, 0.6
				}
				return "installer", ft.Platform, 0.5
			}
		}
	}

	// If all else fails, try to determine from extension
	switch ext {
	case ".exe", ".msi":
		return strings.TrimPrefix(ext, "."), "windows", 0.6
	case ".dmg", ".pkg":
		return strings.TrimPrefix(ext, "."), "macos", 0.6
	case ".deb", ".rpm", ".appimage":
		return strings.TrimPrefix(ext, "."), "linux", 0.6
	default:
		// Try to guess from content type
		mimeExt, _ := mime.ExtensionsByType(contentType)
		if len(mimeExt) > 0 {
			return strings.TrimPrefix(mimeExt[0], "."), "unknown", 0.4
		}
		return "unknown", "unknown", 0.3
	}
}
