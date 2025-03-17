package processor

import (
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/deploymenttheory/go-app-index/internal/downloader"
	"github.com/deploymenttheory/go-app-index/internal/fileanalyzer"
	"github.com/deploymenttheory/go-app-index/internal/logger"
	"github.com/deploymenttheory/go-app-index/internal/storage"
	"github.com/deploymenttheory/go-app-index/internal/types"
)

// Stats holds processor statistics
type Stats struct {
	FilesProcessed int
	Errors         int
	StartTime      time.Time
	EndTime        time.Time
}

// Processor handles file processing and metadata extraction
type Processor struct {
	workers    int
	storage    storage.Storage
	tempDir    string
	inputQueue chan downloader.DownloadResult

	wg         sync.WaitGroup
	stats      Stats
	statsMutex sync.RWMutex

	done      bool
	doneMutex sync.RWMutex
	stop      chan struct{}
}

// New creates a new Processor
func New(workers int, storage storage.Storage, tempDir string) *Processor {
	return &Processor{
		workers:    workers,
		storage:    storage,
		tempDir:    tempDir,
		inputQueue: make(chan downloader.DownloadResult, 100),
		stop:       make(chan struct{}),
	}
}

// Start begins the processing workers
func (p *Processor) Start() {
	p.statsMutex.Lock()
	p.stats.StartTime = time.Now()
	p.statsMutex.Unlock()

	for i := 0; i < p.workers; i++ {
		p.wg.Add(1)
		go p.worker(i)
	}
}

// worker processes downloaded files
func (p *Processor) worker(id int) {
	defer p.wg.Done()

	for {
		select {
		case <-p.stop:
			return
		case result, ok := <-p.inputQueue:
			if !ok {
				return
			}

			// Process the file
			processedFile, err := p.processFile(result)
			if err != nil {
				logger.Errorf("Worker %d: Failed to process %s: %v", id, result.FilePath, err)
				p.incrementErrors()
			} else {
				// Store the processed file info
				err = p.storage.Store(processedFile)
				if err != nil {
					logger.Errorf("Worker %d: Failed to store metadata for %s: %v", id, result.FilePath, err)
					p.incrementErrors()
				}

				p.incrementFilesProcessed()
			}

			// Clean up the temporary file
			os.Remove(result.FilePath)
		}
	}
}

// processFile processes a downloaded file
func (p *Processor) processFile(result downloader.DownloadResult) (types.ProcessedFile, error) {
	// Extract website domain from URL
	domain, err := extractDomain(result.URL)
	if err != nil {
		return types.ProcessedFile{}, fmt.Errorf("failed to extract domain: %w", err)
	}

	// Generate SHA3 hash
	hash, err := generateSHA3Hash(result.FilePath)
	if err != nil {
		return types.ProcessedFile{}, fmt.Errorf("failed to generate hash: %w", err)
	}

	// Create the base processed file
	processedFile := types.ProcessedFile{
		Filename:      result.FileName,
		SourceURL:     result.URL,
		WebsiteDomain: domain,
		DiscoveredAt:  result.DownloadedAt,
		SHA3Hash:      hash,
		FileSizeBytes: result.FileSize,
	}

	// Use enhanced file analysis if possible
	analyzer := fileanalyzer.NewManager()
	analysisResult, err := analyzer.Analyze(result.FilePath, result.ContentType)

	if err == nil && analysisResult.Confidence > 0.5 {
		// Use enhanced analysis results
		logger.Debugf("Using enhanced file analysis for %s: type=%s, platform=%s, confidence=%.2f",
			result.FileName, analysisResult.FileType, analysisResult.Platform, analysisResult.Confidence)

		processedFile.FileType = analysisResult.FileType
		processedFile.Platform = analysisResult.Platform
		processedFile.DetectionScore = analysisResult.Confidence
		processedFile.IsInstaller = analysisResult.IsInstaller

		// Extract additional metadata if available
		if analysisResult.Metadata != nil {
			if version, ok := analysisResult.Metadata["version"].(string); ok {
				processedFile.Version = version
			}

			if publisher, ok := analysisResult.Metadata["publisher"].(string); ok {
				processedFile.Publisher = publisher
			}

			if isSigned, ok := analysisResult.Metadata["is_signed"].(bool); ok {
				processedFile.IsSigned = isSigned
			}

			// Store all metadata
			processedFile.ExtendedMetadata = analysisResult.Metadata
		}
	} else {
		// Fall back to basic detection
		logger.Debugf("Falling back to basic file detection for %s", result.FileName)
		fileType, platform, confidence := downloader.DetectFileType(result.FileName, result.ContentType, "")
		processedFile.FileType = fileType
		processedFile.Platform = platform
		processedFile.DetectionScore = confidence

		// Extract basic metadata
		basicMetadata := extractMetadata(result.FilePath)

		// Convert map[string]string to map[string]interface{}
		extendedMetadata := make(map[string]interface{})
		for k, v := range basicMetadata {
			extendedMetadata[k] = v
		}

		processedFile.ExtendedMetadata = extendedMetadata
	}

	return processedFile, nil
}

// Queue returns the input queue channel
func (p *Processor) Queue() chan<- downloader.DownloadResult {
	return p.inputQueue
}

// Done signals that no more files will be added
func (p *Processor) Done() {
	p.doneMutex.Lock()
	p.done = true
	p.doneMutex.Unlock()
	close(p.inputQueue)
}

// Stop signals the processor to stop
func (p *Processor) Stop() {
	close(p.stop)
}

// Wait waits for all processing to complete
func (p *Processor) Wait() {
	p.wg.Wait()

	p.statsMutex.Lock()
	p.stats.EndTime = time.Now()
	p.statsMutex.Unlock()
}

// Stats returns the current processing statistics
func (p *Processor) Stats() Stats {
	p.statsMutex.RLock()
	defer p.statsMutex.RUnlock()
	return p.stats
}

// Increment files processed counter
func (p *Processor) incrementFilesProcessed() {
	p.statsMutex.Lock()
	p.stats.FilesProcessed++
	p.statsMutex.Unlock()
}

// Increment errors counter
func (p *Processor) incrementErrors() {
	p.statsMutex.Lock()
	p.stats.Errors++
	p.statsMutex.Unlock()
}

func (p *Processor) Duration() time.Duration {
	p.statsMutex.RLock()
	defer p.statsMutex.RUnlock()

	if p.stats.StartTime.IsZero() {
		return 0
	}

	if p.stats.EndTime.IsZero() {
		return time.Since(p.stats.StartTime)
	}

	return p.stats.EndTime.Sub(p.stats.StartTime)
}
