package fileanalyzer

import (
	"os"
	"path/filepath"
	"strings"
)

// ConfidenceFactors stores data used to calculate confidence scores
type ConfidenceFactors struct {
	// Base confidence from primary detection method
	BaseConfidence float64

	// Additional factors that can increase confidence
	ExtensionMatch        bool // If detected type matches file extension
	ContentMatch          bool // If content analysis confirms type
	ValidSignature        bool // If file has a valid digital signature
	ContainsInstallerText bool // If file contains installer-related text
	HasVersionInfo        bool // If version information was extracted

	// Penalty factors that can decrease confidence
	TooSmall           bool // File is too small to be an installer
	UnexpectedContent  bool // Content doesn't match expected format
	MalformedStructure bool // File structure is not as expected
}

// CalculateConfidence computes a confidence score based on various factors
func CalculateConfidence(factors ConfidenceFactors) float64 {
	confidence := factors.BaseConfidence

	// Apply bonuses for positive indicators
	if factors.ExtensionMatch {
		confidence += 0.1
	}
	if factors.ContentMatch {
		confidence += 0.15
	}
	if factors.ValidSignature {
		confidence += 0.2
	}
	if factors.ContainsInstallerText {
		confidence += 0.1
	}
	if factors.HasVersionInfo {
		confidence += 0.05
	}

	// Apply penalties for negative indicators
	if factors.TooSmall {
		confidence -= 0.3
	}
	if factors.UnexpectedContent {
		confidence -= 0.2
	}
	if factors.MalformedStructure {
		confidence -= 0.2
	}

	// Ensure confidence stays within valid range
	if confidence > 1.0 {
		confidence = 1.0
	}
	if confidence < 0.0 {
		confidence = 0.0
	}

	return confidence
}

// IsExtensionMatch checks if the detected file type matches the file extension
func IsExtensionMatch(filePath string, detectedType string) bool {
	ext := strings.ToLower(filepath.Ext(filePath))
	if ext == "" {
		return false
	}

	// Remove leading dot
	ext = ext[1:]

	// Check for direct match
	if ext == detectedType {
		return true
	}

	// Check for common equivalences
	equivalences := map[string][]string{
		"exe":      {"exe", "msi", "com", "bat"},
		"msi":      {"msi", "exe"},
		"dmg":      {"dmg", "pkg"},
		"pkg":      {"pkg", "dmg"},
		"deb":      {"deb"},
		"rpm":      {"rpm"},
		"appimage": {"appimage"},
		"zip":      {"zip", "jar"},
		"jar":      {"jar", "zip"},
		"apk":      {"apk"},
		"ipa":      {"ipa"},
	}

	if equivalents, ok := equivalences[detectedType]; ok {
		for _, equivalent := range equivalents {
			if ext == equivalent {
				return true
			}
		}
	}

	return false
}

// CheckMinimumSize checks if a file meets minimum size requirements for its type
func CheckMinimumSize(filePath string, fileType string) bool {
	// Get file size
	fileInfo, err := os.Stat(filePath)
	if err != nil {
		return false
	}

	size := fileInfo.Size()

	// Minimum sizes for different file types (in bytes)
	minimumSizes := map[string]int64{
		"exe":      50 * 1024,   // 50 KB
		"msi":      100 * 1024,  // 100 KB
		"dmg":      1024 * 1024, // 1 MB
		"pkg":      500 * 1024,  // 500 KB
		"deb":      10 * 1024,   // 10 KB
		"rpm":      10 * 1024,   // 10 KB
		"appimage": 1024 * 1024, // 1 MB
		"jar":      10 * 1024,   // 10 KB
		"apk":      100 * 1024,  // 100 KB
		"ipa":      1024 * 1024, // 1 MB
	}

	// Check against minimum size if specified
	if minSize, ok := minimumSizes[fileType]; ok {
		return size >= minSize
	}

	// Default minimum size for installers (10 KB)
	return size >= 10*1024
}

// AdjustConfidenceBySize adjusts confidence based on file size
func AdjustConfidenceBySize(filePath string, fileType string, baseConfidence float64) float64 {
	// Get file size
	fileInfo, err := os.Stat(filePath)
	if err != nil {
		return baseConfidence
	}

	size := fileInfo.Size()

	// Expected size ranges for different file types
	// Maps file type to (min size, lower typical, upper typical)
	sizeRanges := map[string][3]int64{
		"exe":      {50 * 1024, 1 * 1024 * 1024, 100 * 1024 * 1024},             // 50KB to 100MB
		"msi":      {100 * 1024, 5 * 1024 * 1024, 500 * 1024 * 1024},            // 100KB to 500MB
		"dmg":      {1 * 1024 * 1024, 10 * 1024 * 1024, 2 * 1024 * 1024 * 1024}, // 1MB to 2GB
		"pkg":      {500 * 1024, 5 * 1024 * 1024, 1 * 1024 * 1024 * 1024},       // 500KB to 1GB
		"deb":      {10 * 1024, 1 * 1024 * 1024, 500 * 1024 * 1024},             // 10KB to 500MB
		"rpm":      {10 * 1024, 1 * 1024 * 1024, 500 * 1024 * 1024},             // 10KB to 500MB
		"appimage": {1 * 1024 * 1024, 10 * 1024 * 1024, 1 * 1024 * 1024 * 1024}, // 1MB to 1GB
	}

	// If we have size expectations for this file type
	if ranges, ok := sizeRanges[fileType]; ok {
		minSize := ranges[0]
		lowerTypical := ranges[1]
		upperTypical := ranges[2]

		// Too small: significant confidence reduction
		if size < minSize {
			return baseConfidence * 0.5
		}

		// Within typical range: small confidence boost
		if size >= lowerTypical && size <= upperTypical {
			bonus := baseConfidence * 0.1
			if baseConfidence+bonus > 1.0 {
				return 1.0
			}
			return baseConfidence + bonus
		}

		// Slightly below typical: no change
		if size >= minSize && size < lowerTypical {
			return baseConfidence
		}

		// Above typical but not outrageous: small penalty
		if size > upperTypical && size <= upperTypical*10 {
			return baseConfidence * 0.9
		}

		// Extremely large: bigger penalty
		if size > upperTypical*10 {
			return baseConfidence * 0.7
		}
	}

	return baseConfidence
}
