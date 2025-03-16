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
	FilesStored   int
	UniqueHashes  int
	LastUpdatedAt time.Time
	StartTime     time.Time
	EndTime       time.Time
}
