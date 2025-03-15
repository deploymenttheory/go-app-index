package processor

import (
	"fmt"
	"os"
	"sync"

	"github.com/deploymenttheory/go-app-index/internal/downloader"
	"github.com/deploymenttheory/go-app-index/internal/storage"
	"github.com/deploymenttheory/go-app-index/internal/types"
)

// Stats holds processor statistics
type Stats struct {
	FilesProcessed int
	Errors         int
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
				fmt.Printf("Worker %d: Failed to process %s: %v\n", id, result.FilePath, err)
				p.incrementErrors()
			} else {
				// Store the processed file info
				err = p.storage.Store(processedFile)
				if err != nil {
					fmt.Printf("Worker %d: Failed to store metadata for %s: %v\n", id, result.FilePath, err)
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

	// Detect file type and platform
	fileType, platform := downloader.DetectFileType(result.FileName, result.ContentType)

	return types.ProcessedFile{
		Filename:      result.FileName,
		SourceURL:     result.URL,
		WebsiteDomain: domain,
		DiscoveredAt:  result.DownloadedAt,
		SHA3Hash:      hash,
		FileSizeBytes: result.FileSize,
		Platform:      platform,
		FileType:      fileType,
	}, nil
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
