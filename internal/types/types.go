package types

import (
	"time"
)

// ProcessedFile represents a processed installer file
type ProcessedFile struct {
	// Core fields (original)
	Filename      string    `json:"filename"`
	SourceURL     string    `json:"source_url"`
	WebsiteDomain string    `json:"website_domain"`
	DiscoveredAt  time.Time `json:"discovered_at"`
	SHA3Hash      string    `json:"sha3_hash"`
	FileSizeBytes int64     `json:"file_size_bytes"`
	Platform      string    `json:"platform"`
	FileType      string    `json:"file_type"`

	// Enhanced fields
	DetectionScore   float64                `json:"detection_score,omitempty"`
	IsInstaller      bool                   `json:"is_installer,omitempty"`
	Version          string                 `json:"version,omitempty"`
	Publisher        string                 `json:"publisher,omitempty"`
	IsSigned         bool                   `json:"is_signed,omitempty"`
	ExtendedMetadata map[string]interface{} `json:"extended_metadata,omitempty"`
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
