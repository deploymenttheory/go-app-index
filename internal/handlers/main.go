package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strconv"

	"github.com/deploymenttheory/go-app-index/internal/handlers/dmg"
)

func main() {
	// Define command-line flags
	var (
		listFlag       = flag.Bool("l", false, "List contents of DMG file")
		extractFlag    = flag.Bool("e", false, "Extract file from DMG")
		extractAllFlag = flag.Bool("x", false, "Extract all files from DMG")
		outputDirFlag  = flag.String("o", ".", "Output directory for extraction")
		infoFlag       = flag.Bool("i", false, "Show DMG information")
	)

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: %s [options] dmg-file [file-index]\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "Options:\n")
		flag.PrintDefaults()
	}

	flag.Parse()

	// Check if a DMG file was specified
	args := flag.Args()
	if len(args) < 1 {
		flag.Usage()
		os.Exit(1)
	}

	dmgPath := args[0]

	// Open the DMG file
	handler, file, err := dmg.OpenFile(dmgPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error opening DMG file: %v\n", err)
		os.Exit(1)
	}
	defer file.Close()
	defer handler.Close()

	// Process the command
	if *listFlag {
		// List the contents of the DMG file
		fmt.Printf("Contents of %s:\n", dmgPath)
		fmt.Printf("%-5s %-15s %-15s %s\n", "Index", "Size", "Packed Size", "Name")
		fmt.Println("-----------------------------------------------------")

		for i := 0; i < handler.GetNumberOfFiles(); i++ {
			fileInfo, err := handler.GetFile(i)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error getting file info: %v\n", err)
				continue
			}

			fmt.Printf("%-5d %-15d %-15d %s\n", i, fileInfo.Size, fileInfo.PackSize, fileInfo.Name)
		}
	} else if *extractFlag {
		// Extract a specific file
		if len(args) < 2 {
			fmt.Fprintf(os.Stderr, "Error: file index required for extraction\n")
			flag.Usage()
			os.Exit(1)
		}

		// Parse the file index
		index, err := strconv.Atoi(args[1])
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: invalid file index: %v\n", err)
			os.Exit(1)
		}

		// Get the file info
		fileInfo, err := handler.GetFile(index)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}

		// Generate output filename
		name := fileInfo.Name
		if name == "" {
			name = fmt.Sprintf("file_%d", index)
		}

		// Try to find extension based on Apple filesystem type
		ext := dmg.FindAppleFSExt(name)
		if ext != "" {
			name = "image." + ext
		}

		outPath := filepath.Join(*outputDirFlag, name)

		// Extract the file
		fmt.Printf("Extracting file %d to %s...\n", index, outPath)
		if err := dmg.ExtractFile(handler, file, index, outPath); err != nil {
			fmt.Fprintf(os.Stderr, "Error extracting file: %v\n", err)
			os.Exit(1)
		}

		fmt.Println("Extraction complete.")
	} else if *extractAllFlag {
		// Extract all files
		fmt.Printf("Extracting all files to %s...\n", *outputDirFlag)
		if err := dmg.ExtractAll(handler, file, *outputDirFlag); err != nil {
			fmt.Fprintf(os.Stderr, "Error extracting files: %v\n", err)
			os.Exit(1)
		}
		fmt.Println("Extraction complete.")
	} else if *infoFlag {
		// Show DMG information
		info := dmg.GetInfo(handler)
		fmt.Printf("DMG Information for %s:\n", dmgPath)
		fmt.Printf("Name: %s\n", info.Name)
		fmt.Printf("Number of files: %d\n", info.NumFiles)
		fmt.Printf("Unpacked size: %d bytes\n", info.UnpackedSize)
		fmt.Printf("Packed size: %d bytes\n", info.PackedSize)
		fmt.Printf("Master CRC check: %v\n", info.MasterCrcOK)
		fmt.Printf("Headers check: %v\n", info.HeadersOK)
		fmt.Printf("Data fork check: %v\n", info.DataForkOK)
		fmt.Printf("\nDetailed information:\n%s\n", info.Comment)
	} else {
		// Default action - show basic info
		fmt.Printf("DMG file: %s\n", dmgPath)
		fmt.Printf("Number of files: %d\n", handler.GetNumberOfFiles())
		fmt.Println("Use -l to list contents, -i for detailed info, -e or -x to extract files.")
	}
}
