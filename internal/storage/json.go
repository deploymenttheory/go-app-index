package storage

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"
	"sync"
	"time"

	"github.com/deploymenttheory/go-app-index/internal/logger"
	"github.com/deploymenttheory/go-app-index/internal/types"
)

// JSONOutput represents the JSON output structure
type JSONOutput struct {
	LastUpdated time.Time             `json:"last_updated"`
	Stats       types.StorageStats    `json:"stats"`
	Installers  []types.ProcessedFile `json:"installers"`
}

// JSONStorage implements the Storage interface using a JSON file
type JSONStorage struct {
	filePath  string
	data      JSONOutput
	hashIndex map[string]bool
	urlIndex  map[string]bool
	mutex     sync.RWMutex
}

// New creates a new JSONStorage
func New(filePath string) (*JSONStorage, error) {
	storage := &JSONStorage{
		filePath:  filePath,
		hashIndex: make(map[string]bool),
		urlIndex:  make(map[string]bool),
		data: JSONOutput{
			LastUpdated: time.Now(),
			Stats: types.StorageStats{
				LastUpdatedAt:   time.Now(),
				FilesByPlatform: make(map[string]int),
				FilesByType:     make(map[string]int),
			},
			Installers: make([]types.ProcessedFile, 0),
		},
	}

	// Try to load existing data
	if _, err := os.Stat(filePath); err == nil {
		err = storage.loadExistingData()
		if err != nil {
			return nil, fmt.Errorf("failed to load existing data: %w", err)
		}
	}

	return storage, nil
}

// Store saves a processed file's metadata
func (s *JSONStorage) Store(file types.ProcessedFile) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	// Check if we already have this file by hash or URL
	if s.hashIndex[file.SHA3Hash] || s.urlIndex[file.SourceURL] {
		return nil
	}

	// Add to our data
	s.data.Installers = append(s.data.Installers, file)
	s.hashIndex[file.SHA3Hash] = true
	s.urlIndex[file.SourceURL] = true

	// Update basic stats
	s.data.Stats.FilesStored++
	s.data.Stats.UniqueHashes = len(s.hashIndex)
	s.data.LastUpdated = time.Now()
	s.data.Stats.LastUpdatedAt = time.Now()

	// Update enhanced stats
	s.updateEnhancedStats(file)

	// Write to file
	return s.saveToFile()
}

// updateEnhancedStats updates statistics related to enhanced metadata
func (s *JSONStorage) updateEnhancedStats(file types.ProcessedFile) {
	// Update platform stats
	if file.Platform != "" {
		if s.data.Stats.FilesByPlatform == nil {
			s.data.Stats.FilesByPlatform = make(map[string]int)
		}
		s.data.Stats.FilesByPlatform[file.Platform]++
	}

	// Update file type stats
	if file.FileType != "" {
		if s.data.Stats.FilesByType == nil {
			s.data.Stats.FilesByType = make(map[string]int)
		}
		s.data.Stats.FilesByType[file.FileType]++
	}

	// Update signed installer count
	if file.IsSigned {
		s.data.Stats.SignedInstallerCount++
	}

	// Update versioned file count
	if file.Version != "" {
		s.data.Stats.VersionedFileCount++
	}

	// Update average detection score
	totalScore := s.data.Stats.AvgDetectionScore * float64(s.data.Stats.FilesStored-1)
	totalScore += file.DetectionScore
	s.data.Stats.AvgDetectionScore = totalScore / float64(s.data.Stats.FilesStored)
}

// Close finalizes the storage
func (s *JSONStorage) Close() error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	// Sort the installers
	s.sortInstallers()

	// Update the last updated timestamp
	s.data.LastUpdated = time.Now()
	s.data.Stats.LastUpdatedAt = time.Now()
	s.data.Stats.EndTime = time.Now()

	// Log summary of data
	logger.Infof("Closing storage with %d files stored", s.data.Stats.FilesStored)
	logger.Infof("Files by platform: %v", s.data.Stats.FilesByPlatform)
	logger.Infof("Files by type: %v", s.data.Stats.FilesByType)
	logger.Infof("Signed installer count: %d", s.data.Stats.SignedInstallerCount)
	logger.Infof("Versioned file count: %d", s.data.Stats.VersionedFileCount)
	logger.Infof("Average detection score: %.2f", s.data.Stats.AvgDetectionScore)

	// Write to file
	return s.saveToFile()
}

// Stats returns storage statistics
func (s *JSONStorage) Stats() types.StorageStats {
	s.mutex.RLock()
	defer s.mutex.RUnlock()
	return s.data.Stats
}

// loadExistingData loads existing data from the JSON file
func (s *JSONStorage) loadExistingData() error {
	file, err := os.Open(s.filePath)
	if err != nil {
		return err
	}
	defer file.Close()

	data, err := io.ReadAll(file)
	if err != nil {
		return err
	}

	var output JSONOutput
	if err := json.Unmarshal(data, &output); err != nil {
		return err
	}

	// Initialize maps if not present (for backward compatibility)
	if output.Stats.FilesByPlatform == nil {
		output.Stats.FilesByPlatform = make(map[string]int)
	}
	if output.Stats.FilesByType == nil {
		output.Stats.FilesByType = make(map[string]int)
	}

	// Add existing installers to our indexes
	for _, installer := range output.Installers {
		s.hashIndex[installer.SHA3Hash] = true
		s.urlIndex[installer.SourceURL] = true

		// Rebuild platform and type stats
		if installer.Platform != "" {
			output.Stats.FilesByPlatform[installer.Platform]++
		}
		if installer.FileType != "" {
			output.Stats.FilesByType[installer.FileType]++
		}
		if installer.IsSigned {
			output.Stats.SignedInstallerCount++
		}
		if installer.Version != "" {
			output.Stats.VersionedFileCount++
		}
	}

	// Calculate average detection score if we have files and the score isn't already set
	if output.Stats.FilesStored > 0 && output.Stats.AvgDetectionScore == 0 {
		var totalScore float64
		var countWithScore int
		for _, installer := range output.Installers {
			if installer.DetectionScore > 0 {
				totalScore += installer.DetectionScore
				countWithScore++
			}
		}
		if countWithScore > 0 {
			output.Stats.AvgDetectionScore = totalScore / float64(countWithScore)
		}
	}

	s.data = output
	s.data.Stats.LastUpdatedAt = time.Now()

	logger.Infof("Loaded %d existing installers from %s", len(output.Installers), s.filePath)
	return nil
}

// saveToFile saves the current data to the JSON file
func (s *JSONStorage) saveToFile() error {
	// Sort the installers
	s.sortInstallers()

	// Create the file
	file, err := os.Create(s.filePath)
	if err != nil {
		return err
	}
	defer file.Close()

	// Marshal to JSON
	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")

	return encoder.Encode(s.data)
}

// sortInstallers sorts the installers by domain and filename
func (s *JSONStorage) sortInstallers() {
	sort.Slice(s.data.Installers, func(i, j int) bool {
		// Sort by domain first
		if s.data.Installers[i].WebsiteDomain != s.data.Installers[j].WebsiteDomain {
			return s.data.Installers[i].WebsiteDomain < s.data.Installers[j].WebsiteDomain
		}

		// Then by filename
		return s.data.Installers[i].Filename < s.data.Installers[j].Filename
	})
}
