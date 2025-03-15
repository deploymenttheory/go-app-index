package downloader

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// Stats holds downloader statistics
type Stats struct {
	FilesFound      int
	FilesDownloaded int
	BytesDownloaded int64
	Errors          int
}

// Downloader handles the detection and downloading of installer files
type Downloader struct {
	workers        int
	fileExtensions []string
	tempDir        string
	processorQueue chan<- DownloadResult
	urlQueue       chan string

	wg         sync.WaitGroup
	stats      Stats
	statsMutex sync.RWMutex

	client    *http.Client
	done      bool
	doneMutex sync.RWMutex
	stop      chan struct{}
}

// DownloadResult represents a downloaded file ready for processing
type DownloadResult struct {
	URL          string
	FilePath     string
	FileName     string
	FileSize     int64
	ContentType  string
	DownloadedAt time.Time
}

// New creates a new Downloader
func New(workers int, processorQueue chan<- DownloadResult, fileExtensions []string, tempDir string) *Downloader {
	return &Downloader{
		workers:        workers,
		fileExtensions: fileExtensions,
		tempDir:        tempDir,
		processorQueue: processorQueue,
		urlQueue:       make(chan string, 1000), // Buffer for 1000 URLs
		client: &http.Client{
			Timeout: 5 * time.Minute, // Generous timeout for large files
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				if len(via) >= 10 {
					return fmt.Errorf("too many redirects")
				}
				return nil
			},
		},
		stop: make(chan struct{}),
	}
}

// Start begins the download workers
func (d *Downloader) Start() {
	// Ensure temp directory exists
	if err := os.MkdirAll(d.tempDir, 0755); err != nil {
		fmt.Printf("Failed to create temp directory: %v\n", err)
		return
	}

	// Start worker goroutines
	for i := 0; i < d.workers; i++ {
		d.wg.Add(1)
		go d.worker(i)
	}
}

// worker handles downloading files
func (d *Downloader) worker(id int) {
	defer d.wg.Done()

	for {
		select {
		case <-d.stop:
			return
		case url, ok := <-d.urlQueue:
			if !ok {
				return
			}

			// Check if URL potentially points to an installer
			if !d.isInstallerURL(url) {
				continue
			}

			d.incrementFilesFound()

			// Download the file
			result, err := d.downloadFile(url)
			if err != nil {
				fmt.Printf("Worker %d: Failed to download %s: %v\n", id, url, err)
				d.incrementErrors()
				continue
			}

			// Send to processor
			select {
			case d.processorQueue <- result:
				// Successfully queued
			case <-d.stop:
				// Clean up the downloaded file
				os.Remove(result.FilePath)
				return
			}
		}
	}
}

// downloadFile downloads a file from the given URL
func (d *Downloader) downloadFile(url string) (DownloadResult, error) {
	fmt.Printf("Downloading %s\n", url)

	// Make a HEAD request first to check content type and size
	resp, err := d.client.Head(url)
	if err != nil {
		return DownloadResult{}, fmt.Errorf("head request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return DownloadResult{}, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	contentType := resp.Header.Get("Content-Type")

	// Skip if not a likely binary file
	if !d.isLikelyInstallerContentType(contentType) && !d.hasInstallerExtension(url) {
		return DownloadResult{}, fmt.Errorf("not a likely installer file based on content type: %s", contentType)
	}

	// Create a temporary file
	fileName := filepath.Base(url)
	filePath := filepath.Join(d.tempDir, fmt.Sprintf("%d-%s", time.Now().UnixNano(), fileName))

	// Download the file
	fileResp, err := d.client.Get(url)
	if err != nil {
		return DownloadResult{}, fmt.Errorf("get request failed: %w", err)
	}
	defer fileResp.Body.Close()

	if fileResp.StatusCode != http.StatusOK {
		return DownloadResult{}, fmt.Errorf("unexpected status code: %d", fileResp.StatusCode)
	}

	file, err := os.Create(filePath)
	if err != nil {
		return DownloadResult{}, fmt.Errorf("failed to create file: %w", err)
	}

	// Copy the body to the file
	written, err := io.Copy(file, fileResp.Body)
	file.Close()

	if err != nil {
		os.Remove(filePath)
		return DownloadResult{}, fmt.Errorf("failed to save file: %w", err)
	}

	d.incrementBytesDownloaded(written)
	d.incrementFilesDownloaded()

	return DownloadResult{
		URL:          url,
		FilePath:     filePath,
		FileName:     fileName,
		FileSize:     written,
		ContentType:  contentType,
		DownloadedAt: time.Now(),
	}, nil
}

// Queue returns the URL queue channel
func (d *Downloader) Queue() chan<- string {
	return d.urlQueue
}

// Done signals that no more URLs will be added
func (d *Downloader) Done() {
	d.doneMutex.Lock()
	d.done = true
	d.doneMutex.Unlock()
	close(d.urlQueue)
}

// Stop signals the downloader to stop
func (d *Downloader) Stop() {
	close(d.stop)
}

// Wait waits for all downloads to complete
func (d *Downloader) Wait() {
	d.wg.Wait()
}

// Stats returns the current download statistics
func (d *Downloader) Stats() Stats {
	d.statsMutex.RLock()
	defer d.statsMutex.RUnlock()
	return d.stats
}

// isInstallerURL checks if the URL likely points to an installer file
func (d *Downloader) isInstallerURL(url string) bool {
	return d.hasInstallerExtension(url)
}

// hasInstallerExtension checks if the URL has a known installer extension
func (d *Downloader) hasInstallerExtension(url string) bool {
	lowercaseURL := strings.ToLower(url)
	for _, ext := range d.fileExtensions {
		if strings.HasSuffix(lowercaseURL, strings.ToLower(ext)) {
			return true
		}
	}
	return false
}

// isLikelyInstallerContentType checks if the content type suggests a binary/installer file
func (d *Downloader) isLikelyInstallerContentType(contentType string) bool {
	contentType = strings.ToLower(contentType)

	// Common content types for installers
	knownTypes := []string{
		"application/octet-stream",
		"application/x-msdownload",
		"application/x-msi",
		"application/x-apple-diskimage",
		"application/vnd.debian.binary-package",
		"application/x-rpm",
		"application/x-executable",
	}

	for _, t := range knownTypes {
		if strings.Contains(contentType, t) {
			return true
		}
	}

	return false
}

// Increment files found counter
func (d *Downloader) incrementFilesFound() {
	d.statsMutex.Lock()
	d.stats.FilesFound++
	d.statsMutex.Unlock()
}

// Increment files downloaded counter
func (d *Downloader) incrementFilesDownloaded() {
	d.statsMutex.Lock()
	d.stats.FilesDownloaded++
	d.statsMutex.Unlock()
}

// Increment bytes downloaded counter
func (d *Downloader) incrementBytesDownloaded(bytes int64) {
	d.statsMutex.Lock()
	d.stats.BytesDownloaded += bytes
	d.statsMutex.Unlock()
}

// Increment errors counter
func (d *Downloader) incrementErrors() {
	d.statsMutex.Lock()
	d.stats.Errors++
	d.statsMutex.Unlock()
}
