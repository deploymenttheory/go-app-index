package storage

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"
	"sync"
	"time"

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
				LastUpdatedAt: time.Now(),
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

	// Update stats
	s.data.Stats.FilesStored++
	s.data.Stats.UniqueHashes = len(s.hashIndex)
	s.data.LastUpdated = time.Now()
	s.data.Stats.LastUpdatedAt = time.Now()

	// Write to file
	return s.saveToFile()
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

	// Write to file
	return s.saveToFile()
}

// Stats returns storage statistics
func (s *JSONStorage) Stats() types.StorageStats {
	s.mutex.RLock()
	defer s.mutex.RUnlock()
	return s.data.Stats
}

// Rest of the code remains the same, just update ProcessedFile to types.ProcessedFile

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

	// Add existing installers to our indexes
	for _, installer := range output.Installers {
		s.hashIndex[installer.SHA3Hash] = true
		s.urlIndex[installer.SourceURL] = true
	}

	s.data = output
	s.data.Stats.LastUpdatedAt = time.Now()

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
