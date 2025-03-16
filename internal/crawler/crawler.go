package crawler

import (
	"fmt"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/deploymenttheory/go-app-index/internal/logger"
	"github.com/gocolly/colly/v2"
)

// Stats holds crawler statistics
type Stats struct {
	URLsVisited int
	URLsSkipped int
	URLsQueued  int
}

// Crawler handles the website crawling and URL discovery
type Crawler struct {
	workers         int
	startURL        string
	maxDepth        int
	includePatterns []*regexp.Regexp
	excludePatterns []*regexp.Regexp
	delay           int
	downloadQueue   chan<- string

	collector    *colly.Collector
	visited      map[string]bool
	visitedMutex sync.RWMutex
	stats        Stats
	statsMutex   sync.RWMutex

	done      chan struct{}
	stopped   bool
	stopMutex sync.RWMutex
}

// New creates a new Crawler
func New(workers int, startURL string, maxDepth int, includePatterns, excludePatterns []string, delay int, downloadQueue chan<- string) *Crawler {
	c := &Crawler{
		workers:       workers,
		startURL:      startURL,
		maxDepth:      maxDepth,
		delay:         delay,
		downloadQueue: downloadQueue,
		visited:       make(map[string]bool),
		done:          make(chan struct{}),
		stopped:       false,
	}

	// Compile regex patterns
	c.includePatterns = make([]*regexp.Regexp, 0, len(includePatterns))
	for _, pattern := range includePatterns {
		logger.Debugf("Compiling include pattern: %q", pattern)
		if pattern == "" {
			logger.Warningf("Empty include pattern will not match any URLs")
			continue
		}
		re, err := regexp.Compile(pattern)
		if err != nil {
			logger.Warningf("Invalid include pattern %q: %v", pattern, err)
			continue
		}
		c.includePatterns = append(c.includePatterns, re)
	}

	c.excludePatterns = make([]*regexp.Regexp, 0, len(excludePatterns))
	for _, pattern := range excludePatterns {
		logger.Debugf("Compiling exclude pattern: %q", pattern)
		re, err := regexp.Compile(pattern)
		if err != nil {
			logger.Warningf("Invalid exclude pattern %q: %v", pattern, err)
			continue
		}
		c.excludePatterns = append(c.excludePatterns, re)
	}

	return c
}

// Run starts the crawler
func (c *Crawler) Run() error {
	// Initialize collector
	c.collector = colly.NewCollector(
		colly.MaxDepth(c.maxDepth),
		colly.Async(true),
	)

	// Limit parallelism
	err := c.collector.Limit(&colly.LimitRule{
		DomainGlob:  "*",
		Parallelism: c.workers,
		Delay:       time.Duration(c.delay) * time.Millisecond,
	})
	if err != nil {
		return fmt.Errorf("failed to set limit rule: %w", err)
	}

	// Setup callbacks
	c.collector.OnHTML("a[href]", func(e *colly.HTMLElement) {
		link := e.Request.AbsoluteURL(e.Attr("href"))
		if link == "" {
			logger.Debugf("Found empty link, skipping")
			return
		}

		logger.Debugf("Found link: %s", link)

		// Skip if already visited
		c.visitedMutex.RLock()
		visited := c.visited[link]
		c.visitedMutex.RUnlock()
		if visited {
			logger.Debugf("Already visited: %s, skipping", link)
			return
		}

		// Check URL against filter patterns
		if c.shouldSkipURL(link) {
			logger.Debugf("Filtered out by patterns: %s, skipping", link)
			c.incrementSkipped()
			return
		}

		// Check if it's a potential installer file
		if c.isPotentialInstallerURL(link) {
			logger.Infof("Potential installer: %s, sending to downloader", link)
			c.sendToDownloader(link)
			return
		}

		// Visit the link
		c.visitedMutex.Lock()
		c.visited[link] = true
		c.visitedMutex.Unlock()

		c.incrementVisited()

		// Check if we should stop
		if c.isStopped() {
			return
		}

		// Follow the link
		logger.Debugf("Following link: %s", link)
		err := e.Request.Visit(link)
		if err != nil {
			logger.Warningf("Failed to visit %s: %v", link, err)
		}
	})

	c.collector.OnRequest(func(r *colly.Request) {
		if c.isStopped() {
			r.Abort()
			return
		}
		logger.Infof("Visiting %s (Depth: %d)", r.URL.String(), r.Depth)
	})

	c.collector.OnResponse(func(r *colly.Response) {
		logger.Debugf("Got response from %s: status=%d, length=%d",
			r.Request.URL, r.StatusCode, len(r.Body))

		// Print first 200 chars of body in debug mode
		if logger.LogLevel >= logger.LevelDebug {
			preview := string(r.Body)
			if len(preview) > 200 {
				preview = preview[:200] + "..."
			}
			logger.Debugf("Response preview: %s", preview)
		}
	})

	c.collector.OnError(func(r *colly.Response, err error) {
		logger.Warningf("Error on %s: %v", r.Request.URL, err)
	})

	// Print debug info before starting
	logger.Infof("Crawler starting with settings:")
	logger.Infof("  Start URL: %s", c.startURL)
	logger.Infof("  Max depth: %d", c.maxDepth)
	logger.Debugf("  Include patterns: %d patterns", len(c.includePatterns))
	logger.Debugf("  Exclude patterns: %d patterns", len(c.excludePatterns))

	// Start the crawler
	logger.Infof("Starting the crawl at %s", c.startURL)
	err = c.collector.Visit(c.startURL)
	if err != nil {
		return fmt.Errorf("failed to start crawler: %w", err)
	}

	// Wait for crawling to complete
	logger.Infof("Waiting for crawling to complete...")
	c.collector.Wait()
	logger.Infof("Crawling completed")

	// Signal completion
	close(c.done)
	return nil
}

// Done returns a channel that's closed when crawling is complete
func (c *Crawler) Done() <-chan struct{} {
	return c.done
}

// Stop signals the crawler to stop
func (c *Crawler) Stop() {
	c.stopMutex.Lock()
	c.stopped = true
	c.stopMutex.Unlock()
	c.collector.Wait()
}

// Stats returns the current crawler statistics
func (c *Crawler) Stats() Stats {
	c.statsMutex.RLock()
	defer c.statsMutex.RUnlock()
	return c.stats
}

// Check if crawler has been stopped
func (c *Crawler) isStopped() bool {
	c.stopMutex.RLock()
	defer c.stopMutex.RUnlock()
	return c.stopped
}

// Check if URL should be skipped based on patterns
func (c *Crawler) shouldSkipURL(url string) bool {
	// If include patterns exist, URL must match at least one
	if len(c.includePatterns) > 0 {
		matched := false
		for _, re := range c.includePatterns {
			if re.MatchString(url) {
				matched = true
				logger.Debugf("URL %s matched include pattern %v", url, re)
				break
			}
		}
		if !matched {
			logger.Debugf("URL %s did not match any include patterns, skipping", url)
			return true
		}
	}

	// If URL matches any exclude pattern, skip it
	for _, re := range c.excludePatterns {
		if re.MatchString(url) {
			logger.Debugf("URL %s matched exclude pattern %v, skipping", url, re)
			return true
		}
	}

	return false
}

// Check if URL potentially points to an installer file
func (c *Crawler) isPotentialInstallerURL(url string) bool {
	// Will be implemented in the downloadQueue component
	// This is a basic implementation for now
	// Checking common installer file extensions in URL
	knownExtensions := []string{".exe", ".msi", ".dmg", ".pkg", ".deb", ".rpm", ".AppImage"}

	for _, ext := range knownExtensions {
		if strings.HasSuffix(strings.ToLower(url), ext) {
			logger.Debugf("URL %s has installer extension %s", url, ext)
			return true
		}
	}

	return false
}

// Send URL to the download queue
func (c *Crawler) sendToDownloader(url string) {
	// Send non-blocking, if queue is full, just log it
	select {
	case c.downloadQueue <- url:
		c.incrementQueued()
		logger.Debugf("Sent to download queue: %s", url)
	default:
		logger.Warningf("Download queue is full, skipping %s", url)
	}
}

// Increment URLs visited counter
func (c *Crawler) incrementVisited() {
	c.statsMutex.Lock()
	c.stats.URLsVisited++
	c.statsMutex.Unlock()
}

// Increment URLs skipped counter
func (c *Crawler) incrementSkipped() {
	c.statsMutex.Lock()
	c.stats.URLsSkipped++
	c.statsMutex.Unlock()
}

// Increment URLs queued counter
func (c *Crawler) incrementQueued() {
	c.statsMutex.Lock()
	c.stats.URLsQueued++
	c.statsMutex.Unlock()
}
