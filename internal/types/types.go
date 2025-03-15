package types

import (
	"time"
)

// ProcessedFile represents a processed installer file
type ProcessedFile struct {
	Filename      string    `json:"filename"`
	SourceURL     string    `json:"source_url"`
	WebsiteDomain string    `json:"website_domain"`
	DiscoveredAt  time.Time `json:"discovered_at"`
	SHA3Hash      string    `json:"sha3_hash"`
	FileSizeBytes int64     `json:"file_size_bytes"`
	Platform      string    `json:"platform"`
	FileType      string    `json:"file_type"`
}

// StorageStats holds storage statistics
type StorageStats struct {
	FilesStored   int
	UniqueHashes  int
	LastUpdatedAt time.Time
}
