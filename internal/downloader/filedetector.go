package downloader

import (
	"mime"
	"path/filepath"
	"strings"
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
func DetectFileType(fileName, contentType string) (fileType, platform string) {
	ext := strings.ToLower(filepath.Ext(fileName))
	lowerContentType := strings.ToLower(contentType)

	// Try to detect by extension first
	for _, ft := range knownFileTypes {
		for _, e := range ft.Extensions {
			if e == ext {
				return strings.TrimPrefix(ext, "."), ft.Platform
			}
		}
	}

	// If extension check fails, try by MIME type
	for _, ft := range knownFileTypes {
		for _, mt := range ft.MimeTypes {
			if strings.Contains(lowerContentType, mt) {
				// Use extension if available, otherwise use generic name
				if ext != "" {
					return strings.TrimPrefix(ext, "."), ft.Platform
				}
				return "installer", ft.Platform
			}
		}
	}

	// If all else fails, try to determine from extension
	switch ext {
	case ".exe", ".msi":
		return strings.TrimPrefix(ext, "."), "windows"
	case ".dmg", ".pkg":
		return strings.TrimPrefix(ext, "."), "macos"
	case ".deb", ".rpm", ".appimage":
		return strings.TrimPrefix(ext, "."), "linux"
	default:
		// Try to guess from content type
		mimeExt, _ := mime.ExtensionsByType(contentType)
		if len(mimeExt) > 0 {
			return strings.TrimPrefix(mimeExt[0], "."), "unknown"
		}
		return "unknown", "unknown"
	}
}
