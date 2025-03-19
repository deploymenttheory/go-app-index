package fileanalyzer

import (
	"fmt"
	"time"

	"github.com/deploymenttheory/go-app-index/internal/logger"
)

// Result represents the analysis result for a file
type Result struct {
	FileType     string                 // Type of file (exe, msi, dmg, etc.)
	Platform     string                 // Target platform
	Confidence   float64                // Confidence score (0.0-1.0)
	IsInstaller  bool                   // Whether this is an installer
	Metadata     map[string]interface{} // Extended metadata
	AnalyzedAt   time.Time              // When analysis was performed
	NestedResult *Result                // Analysis result for a file inside a container (e.g. zip)
}

// Analyzer defines the interface for file analyzers
type Analyzer interface {
	// Analyze performs analysis on a file path
	Analyze(filePath string) (*Result, error)

	// CanHandle checks if this analyzer can handle this file type
	CanHandle(filePath string, contentType string) bool
}

// Manager orchestrates the file analysis process
type Manager struct {
	analyzers []Analyzer
}

// NewManager creates a new analyzer manager with all available analyzers
func NewManager() *Manager {
	m := &Manager{
		analyzers: make([]Analyzer, 0),
	}

	// Register all analyzers - specialized analyzers first
	// MSI has higher priority than PE for .msi files
	m.RegisterAnalyzer(&MSIAnalyzer{})
	m.RegisterAnalyzer(&RPMAnalyzer{})
	m.RegisterAnalyzer(&DEBAnalyzer{})

	// Then register general analyzers
	m.RegisterAnalyzer(&PEAnalyzer{})
	m.RegisterAnalyzer(&MacOSAnalyzer{})
	m.RegisterAnalyzer(&ZipAnalyzer{})
	m.RegisterAnalyzer(&LinuxAnalyzer{})

	// ContentAnalyzer is the fallback
	m.RegisterAnalyzer(&ContentAnalyzer{})

	return m
}

// RegisterAnalyzer adds an analyzer to the manager
func (m *Manager) RegisterAnalyzer(analyzer Analyzer) {
	m.analyzers = append(m.analyzers, analyzer)
}

// Analyze performs analysis on a file using all registered analyzers
func (m *Manager) Analyze(filePath string, contentType string) (*Result, error) {
	logger.Debugf("Analyzing file: %s", filePath)

	// Default result with low confidence
	defaultResult := &Result{
		FileType:    "unknown",
		Platform:    "unknown",
		Confidence:  0.1,
		IsInstaller: false,
		Metadata:    make(map[string]interface{}),
		AnalyzedAt:  time.Now(),
	}

	// Find analyzers that can handle this file
	var applicableAnalyzers []Analyzer
	for _, analyzer := range m.analyzers {
		if analyzer.CanHandle(filePath, contentType) {
			applicableAnalyzers = append(applicableAnalyzers, analyzer)
		}
	}

	if len(applicableAnalyzers) == 0 {
		logger.Debugf("No applicable analyzers found for file: %s", filePath)
		return defaultResult, nil
	}

	// Run all applicable analyzers and select the result with highest confidence
	var bestResult *Result
	var bestConfidence float64

	for _, analyzer := range applicableAnalyzers {
		result, err := analyzer.Analyze(filePath)
		if err != nil {
			logger.Debugf("Analyzer error: %v", err)
			continue
		}

		if result != nil {
			// Handle nested results - give preference to container files with confirmed installers inside
			if result.NestedResult != nil && result.NestedResult.IsInstaller {
				// Boost confidence for archives that contain confirmed installers
				adjustedConfidence := result.Confidence + 0.1
				if adjustedConfidence > 1.0 {
					adjustedConfidence = 1.0
				}

				// If this is a container with a high-confidence installer inside, prefer it
				if adjustedConfidence > bestConfidence {
					result.Confidence = adjustedConfidence
					bestResult = result
					bestConfidence = adjustedConfidence
				}
			} else if result.Confidence > bestConfidence {
				// Standard confidence comparison
				bestResult = result
				bestConfidence = result.Confidence
			}
		}
	}

	if bestResult != nil {
		// Log the result and any nested results
		if bestResult.NestedResult != nil {
			logger.Debugf("Best analysis result for %s: type=%s, platform=%s, confidence=%.2f (contains: %s/%s)",
				filePath, bestResult.FileType, bestResult.Platform, bestResult.Confidence,
				bestResult.NestedResult.FileType, bestResult.NestedResult.Platform)
		} else {
			logger.Debugf("Best analysis result for %s: type=%s, platform=%s, confidence=%.2f",
				filePath, bestResult.FileType, bestResult.Platform, bestResult.Confidence)
		}

		// Add installer metadata shortcuts to top level (for backward compatibility)
		if installerName, ok := bestResult.Metadata["name"]; ok {
			if _, exists := bestResult.Metadata["product_name"]; !exists {
				bestResult.Metadata["product_name"] = installerName
			}
		}

		if installerVersion, ok := bestResult.Metadata["version"]; ok {
			if _, exists := bestResult.Metadata["product_version"]; !exists {
				bestResult.Metadata["product_version"] = installerVersion
			}
		}

		return bestResult, nil
	}

	return defaultResult, fmt.Errorf("no successful analysis")
}

// AnalyzeNestedFile is a helper method to analyze a file within a container
func (m *Manager) AnalyzeNestedFile(filePath string, contentType string) (*Result, error) {
	// Use a different log prefix for nested analysis
	logger.Debugf("Analyzing nested file: %s", filePath)

	// Run analysis with all analyzers except the one for the container type
	// to avoid potential infinite recursion
	var applicableAnalyzers []Analyzer
	for _, analyzer := range m.analyzers {
		// Skip the package analyzer to prevent recursion
		if _, isPackageAnalyzer := analyzer.(*ZipAnalyzer); !isPackageAnalyzer {
			if analyzer.CanHandle(filePath, contentType) {
				applicableAnalyzers = append(applicableAnalyzers, analyzer)
			}
		}
	}

	// If no applicable analyzers, return a default result
	if len(applicableAnalyzers) == 0 {
		return &Result{
			FileType:    "unknown",
			Platform:    "unknown",
			Confidence:  0.1,
			IsInstaller: false,
			Metadata:    make(map[string]interface{}),
			AnalyzedAt:  time.Now(),
		}, nil
	}

	// Find the best result
	var bestResult *Result
	var bestConfidence float64

	for _, analyzer := range applicableAnalyzers {
		result, err := analyzer.Analyze(filePath)
		if err != nil {
			continue
		}

		if result != nil && result.Confidence > bestConfidence {
			bestResult = result
			bestConfidence = result.Confidence
		}
	}

	if bestResult != nil {
		return bestResult, nil
	}

	return &Result{
		FileType:    "unknown",
		Platform:    "unknown",
		Confidence:  0.1,
		IsInstaller: false,
		Metadata:    make(map[string]interface{}),
		AnalyzedAt:  time.Now(),
	}, fmt.Errorf("no successful nested analysis")
}
