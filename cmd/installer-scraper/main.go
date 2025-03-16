// In main.go, update your code:

package main

import (
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/deploymenttheory/go-app-index/internal/config"
	"github.com/deploymenttheory/go-app-index/internal/crawler"
	"github.com/deploymenttheory/go-app-index/internal/downloader"
	"github.com/deploymenttheory/go-app-index/internal/logger"
	"github.com/deploymenttheory/go-app-index/internal/processor"
	"github.com/deploymenttheory/go-app-index/internal/storage"
)

var (
	cfgFile string
	cfg     config.Config
)

func main() {
	rootCmd := &cobra.Command{
		Use:   "installer-scraper",
		Short: "Scrape websites for installer files",
		Long: `A web scraper that finds installer files (.exe, .msi, .dmg, .pkg, etc.)
from specified websites, computes their SHA3 hash, and stores metadata to a JSON file.`,
		PersistentPreRun: setupLogging,
		Run:              runScraper,
	}

	// Global flags
	rootCmd.PersistentFlags().StringVarP(&cfgFile, "config", "c", "", "config file (default is ./config.yaml)")

	// Logging flags
	rootCmd.PersistentFlags().BoolP("verbose", "v", false, "enable verbose debugging output")
	rootCmd.PersistentFlags().Bool("no-color", false, "disable colored output")
	rootCmd.PersistentFlags().String("log-file", "", "log to file instead of stdout")

	// Required flags
	rootCmd.Flags().StringP("url", "u", "", "URL to start scraping (required)")
	rootCmd.MarkFlagRequired("url")

	// Optional flags (same as before)
	rootCmd.Flags().StringP("output", "o", "installers.json", "output JSON file")
	rootCmd.Flags().IntP("depth", "d", 3, "maximum crawl depth")
	rootCmd.Flags().StringSliceP("extensions", "e",
		[]string{".exe", ".msi", ".dmg", ".pkg", ".deb", ".rpm", ".AppImage"},
		"file extensions to look for")
	rootCmd.Flags().StringSliceP("include", "i", []string{}, "regex patterns to include URLs")
	rootCmd.Flags().StringSliceP("exclude", "x", []string{}, "regex patterns to exclude URLs")
	rootCmd.Flags().String("temp-dir", os.TempDir(), "temporary directory for downloads")

	// Concurrency flags (same as before)
	rootCmd.Flags().IntP("crawler-workers", "w", 10, "number of crawler workers")
	rootCmd.Flags().IntP("download-workers", "W", 5, "number of download workers")
	rootCmd.Flags().IntP("processor-workers", "p", 3, "number of processor workers")
	rootCmd.Flags().IntP("delay", "D", 200, "delay between requests in milliseconds")

	// Execute
	if err := rootCmd.Execute(); err != nil {
		logger.Errorf("Error executing command: %v", err)
		os.Exit(1)
	}
}

// setupLogging configures the logger based on command line flags
func setupLogging(cmd *cobra.Command, args []string) {
	// Check for verbose flag
	verbose, _ := cmd.Flags().GetBool("verbose")
	if verbose {
		logger.SetLevel(logger.LevelDebug)
		logger.Infof("Debug logging enabled")
	} else {
		logger.SetLevel(logger.LevelInfo)
	}

	// Check for no-color flag
	noColor, _ := cmd.Flags().GetBool("no-color")
	if noColor {
		logger.DisableColors()
	}

	// Check for log file
	logFile, _ := cmd.Flags().GetString("log-file")
	if logFile != "" {
		// Open log file
		file, err := os.OpenFile(logFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
		if err != nil {
			logger.Errorf("Failed to open log file: %v", err)
		} else {
			// Disable colors when logging to file
			logger.DisableColors()
			// Set up loggers with file output
			logger.Initialize(file, file, file, file)
			logger.Infof("Logging to file: %s", logFile)
		}
	}
}

func runScraper(cmd *cobra.Command, args []string) {
	// Parse config from command line flags
	var err error
	cfg, err = parseConfig(cmd)
	if err != nil {
		logger.Errorf("Error parsing configuration: %v", err)
		os.Exit(1)
	}

	overallStartTime := time.Now()

	logger.Infof("Starting scraper for %s with depth %d", cfg.StartURL, cfg.MaxDepth)
	logger.Infof("Looking for file extensions: %v", cfg.FileExtensions)

	// Setup signal handling for graceful shutdown
	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan, syscall.SIGINT, syscall.SIGTERM)

	// Initialize components
	store, err := storage.New(cfg.OutputFile)
	if err != nil {
		logger.Errorf("Failed to initialize storage: %v", err)
		os.Exit(1)
	}

	proc := processor.New(cfg.ProcessorWorkers, store, cfg.TempDir)
	down := downloader.New(cfg.DownloadWorkers, proc.Queue(), cfg.FileExtensions, cfg.TempDir)
	crawl := crawler.New(cfg.CrawlerWorkers, cfg.StartURL, cfg.MaxDepth,
		cfg.IncludePatterns, cfg.ExcludePatterns, cfg.Delay, down.Queue())

	// Start components
	proc.Start()
	down.Start()

	// Run crawler (blocking until complete or interrupted)
	go func() {
		if err := crawl.Run(); err != nil {
			logger.Errorf("Crawler error: %v", err)
		}
		// Signal we're done discovering URLs
		down.Done()
	}()

	// Wait for completion or interrupt
	select {
	case <-crawl.Done():
		logger.Infof("Crawling complete, waiting for processing to finish...")
		down.Wait()
		proc.Done()
		proc.Wait()
		store.Close()
	case sig := <-signalChan:
		logger.Infof("Received signal %v, shutting down gracefully...", sig)
		crawl.Stop()
		down.Stop()
		proc.Stop()
		store.Close()
	}

	overallDuration := time.Since(overallStartTime)

	// Final stats
	logger.Infof("Scraper completed in %v", overallDuration)
	logger.Infof("Component timing:")
	logger.Infof("  - Crawler:    %v", crawl.Duration())
	logger.Infof("  - Downloader: %v", down.Duration())
	logger.Infof("  - Processor:  %v", proc.Duration())

	logger.Infof("URLs visited: %d", crawl.Stats().URLsVisited)
	logger.Infof("URLs visited: %d", crawl.Stats().URLsVisited)
	logger.Infof("URLs skipped: %d", crawl.Stats().URLsSkipped)
	logger.Infof("Files found: %d", down.Stats().FilesFound)
	logger.Infof("Files processed: %d", proc.Stats().FilesProcessed)
	logger.Infof("Results saved to: %s", cfg.OutputFile)
}

func parseConfig(cmd *cobra.Command) (config.Config, error) {
	// If config file is specified, load it first
	if cfgFile != "" {
		// TODO: Implement config file loading
	}

	// Command line flags override config file
	url, _ := cmd.Flags().GetString("url")
	output, _ := cmd.Flags().GetString("output")
	depth, _ := cmd.Flags().GetInt("depth")
	extensions, _ := cmd.Flags().GetStringSlice("extensions")
	includes, _ := cmd.Flags().GetStringSlice("include")
	excludes, _ := cmd.Flags().GetStringSlice("exclude")
	tempDir, _ := cmd.Flags().GetString("temp-dir")

	crawlerWorkers, _ := cmd.Flags().GetInt("crawler-workers")
	downloadWorkers, _ := cmd.Flags().GetInt("download-workers")
	processorWorkers, _ := cmd.Flags().GetInt("processor-workers")
	delay, _ := cmd.Flags().GetInt("delay")

	return config.Config{
		StartURL:         url,
		OutputFile:       output,
		MaxDepth:         depth,
		FileExtensions:   extensions,
		IncludePatterns:  includes,
		ExcludePatterns:  excludes,
		TempDir:          tempDir,
		CrawlerWorkers:   crawlerWorkers,
		DownloadWorkers:  downloadWorkers,
		ProcessorWorkers: processorWorkers,
		Delay:            delay,
	}, nil
}
