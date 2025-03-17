package config

// Config holds the application configuration
type Config struct {
	// Main settings
	StartURL        string
	OutputFile      string
	MaxDepth        int
	FileExtensions  []string
	IncludePatterns []string
	ExcludePatterns []string
	TempDir         string

	// Concurrency settings
	CrawlerWorkers   int
	DownloadWorkers  int
	ProcessorWorkers int
	Delay            int // in milliseconds

	// Timeout settings
	RequestTimeout int // in seconds
}
