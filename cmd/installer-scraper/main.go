package main

import (
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/spf13/cobra"

	"github.com/deploymenttheory/go-app-index/internal/config"
	"github.com/deploymenttheory/go-app-index/internal/crawler"
	"github.com/deploymenttheory/go-app-index/internal/downloader"
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
		Run: runScraper,
	}

	// Global flags
	rootCmd.PersistentFlags().StringVarP(&cfgFile, "config", "c", "", "config file (default is ./config.yaml)")

	// Required flags
	rootCmd.Flags().StringP("url", "u", "", "URL to start scraping (required)")
	rootCmd.MarkFlagRequired("url")

	// Optional flags
	rootCmd.Flags().StringP("output", "o", "installers.json", "output JSON file")
	rootCmd.Flags().IntP("depth", "d", 3, "maximum crawl depth")
	rootCmd.Flags().StringSliceP("extensions", "e",
		[]string{".exe", ".msi", ".dmg", ".pkg", ".deb", ".rpm", ".AppImage"},
		"file extensions to look for")
	rootCmd.Flags().StringSliceP("include", "i", []string{}, "regex patterns to include URLs")
	rootCmd.Flags().StringSliceP("exclude", "x", []string{}, "regex patterns to exclude URLs")
	rootCmd.Flags().String("temp-dir", os.TempDir(), "temporary directory for downloads")

	// Concurrency flags
	rootCmd.Flags().IntP("crawler-workers", "w", 10, "number of crawler workers")
	rootCmd.Flags().IntP("download-workers", "W", 5, "number of download workers")
	rootCmd.Flags().IntP("processor-workers", "p", 3, "number of processor workers")
	rootCmd.Flags().IntP("delay", "D", 200, "delay between requests in milliseconds")

	// Execute
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func runScraper(cmd *cobra.Command, args []string) {
	// Parse config from command line flags
	var err error
	cfg, err = parseConfig(cmd)
	if err != nil {
		fmt.Printf("Error parsing configuration: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Starting scraper for %s with depth %d\n", cfg.StartURL, cfg.MaxDepth)
	fmt.Printf("Looking for file extensions: %v\n", cfg.FileExtensions)

	// Setup signal handling for graceful shutdown
	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan, syscall.SIGINT, syscall.SIGTERM)

	// Initialize components
	store, err := storage.New(cfg.OutputFile)
	if err != nil {
		fmt.Printf("Failed to initialize storage: %v\n", err)
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
			fmt.Printf("Crawler error: %v\n", err)
		}
		// Signal we're done discovering URLs
		down.Done()
	}()

	// Wait for completion or interrupt
	select {
	case <-crawl.Done():
		fmt.Println("Crawling complete, waiting for processing to finish...")
		down.Wait()
		proc.Done()
		proc.Wait()
	case sig := <-signalChan:
		fmt.Printf("Received signal %v, shutting down gracefully...\n", sig)
		crawl.Stop()
		down.Stop()
		proc.Stop()
	}

	// Final stats
	fmt.Println("Scraper completed")
	fmt.Printf("URLs visited: %d\n", crawl.Stats().URLsVisited)
	fmt.Printf("URLs skipped: %d\n", crawl.Stats().URLsSkipped)
	fmt.Printf("Files found: %d\n", down.Stats().FilesFound)
	fmt.Printf("Files processed: %d\n", proc.Stats().FilesProcessed)
	fmt.Printf("Results saved to: %s\n", cfg.OutputFile)
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
