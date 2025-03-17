package storage

import (
	"time"

	"github.com/deploymenttheory/go-app-index/internal/types"
)

// Storage defines the interface for storing installer file metadata
type Storage interface {
	// Store saves a processed file's metadata
	Store(file types.ProcessedFile) error

	// Close finalizes the storage
	Close() error

	// Stats returns storage statistics
	Stats() types.StorageStats
}

// StorageStats holds storage statistics
type StorageStats struct {
	FilesStored   int       `json:"files_stored"`
	UniqueHashes  int       `json:"unique_hashes"`
	LastUpdatedAt time.Time `json:"last_updated_at"`
	StartTime     time.Time `json:"start_time,omitempty"`
	EndTime       time.Time `json:"end_time,omitempty"`

	// Enhanced stats
	FilesByPlatform      map[string]int `json:"files_by_platform,omitempty"`
	FilesByType          map[string]int `json:"files_by_type,omitempty"`
	AvgDetectionScore    float64        `json:"avg_detection_score,omitempty"`
	SignedInstallerCount int            `json:"signed_installer_count,omitempty"`
	VersionedFileCount   int            `json:"versioned_file_count,omitempty"`
}
