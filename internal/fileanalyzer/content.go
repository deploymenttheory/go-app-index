package fileanalyzer

import (
	"bufio"
	"bytes"
	"io"
	"os"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf8"
)

type ContentAnalyzer struct{}

// CanHandle returns true as content analysis can handle any file
func (a *ContentAnalyzer) CanHandle(filePath string, contentType string) bool {
	return true
}

// Analyze performs content-based analysis on the file
func (a *ContentAnalyzer) Analyze(filePath string) (*Result, error) {
	metadata := make(map[string]interface{})

	// Try to determine file format from content
	fileFormat, confidence := detectFileFormat(filePath)

	// Check for executable bits
	if detectExecutableBits(filePath) {
		metadata["has_executable_bits"] = true
	}

	// Check for installer strings
	hasInstallerStrings, installerMatches := detectInstallStrings(filePath)
	if hasInstallerStrings {
		metadata["has_installer_strings"] = true
		metadata["installer_matches"] = installerMatches[:min(5, len(installerMatches))]
	}

	// Try to extract version info
	sample, err := readFileSample(filePath, 8192)
	if err == nil {
		if version := extractCommonVersionPattern(sample); version != "" {
			metadata["version"] = version
		}
	}

	// Determine platform from file format
	platform := "unknown"
	switch fileFormat {
	case "elf":
		platform = "linux"
	case "pe/exe":
		platform = "windows"
	case "macho":
		platform = "macos"
	}

	return &Result{
		FileType:    fileFormat,
		Platform:    platform,
		Confidence:  confidence,
		IsInstaller: hasInstallerStrings,
		Metadata:    metadata,
		AnalyzedAt:  timeNow(),
	}, nil
}

// ContentAnalyzer provides utility functions for analyzing file content
// These functions are used by the specific analyzers

// readFileSample reads a sample of bytes from the beginning of a file
func readFileSample(filePath string, size int) ([]byte, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	buffer := make([]byte, size)
	n, err := io.ReadAtLeast(file, buffer, 1)
	if err != nil && err != io.EOF && err != io.ErrUnexpectedEOF {
		return nil, err
	}

	return buffer[:n], nil
}

// isTextFile checks if a file is likely a text file
func isTextFile(filePath string) (bool, error) {
	sample, err := readFileSample(filePath, 8192)
	if err != nil {
		return false, err
	}

	// Check for common binary file signatures
	binarySignatures := [][]byte{
		{0x7F, 'E', 'L', 'F'},    // ELF
		{0x4D, 0x5A},             // DOS/PE
		{0xCA, 0xFE, 0xBA, 0xBE}, // Java class
		{0x50, 0x4B, 0x03, 0x04}, // ZIP
		{0x1F, 0x8B},             // GZIP
		{0x42, 0x5A, 0x68},       // BZIP2
		{0xFF, 0xD8, 0xFF},       // JPEG
		{0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A}, // PNG
	}

	for _, sig := range binarySignatures {
		if len(sample) >= len(sig) && bytes.Equal(sample[:len(sig)], sig) {
			return false, nil
		}
	}

	// Check if the file contains null bytes (common in binary files)
	if bytes.IndexByte(sample, 0) != -1 {
		return false, nil
	}

	// Check if the content is valid UTF-8
	return utf8.Valid(sample), nil
}

// extractCommonVersionPattern extracts a version string from content
func extractCommonVersionPattern(content []byte) string {
	// Common version patterns
	versionPatterns := []*regexp.Regexp{
		regexp.MustCompile(`(?i)version[\s="':]+([0-9]+\.[0-9]+(\.[0-9]+)?)`),
		regexp.MustCompile(`(?i)v([0-9]+\.[0-9]+(\.[0-9]+)?)`),
		regexp.MustCompile(`(?i)([0-9]+\.[0-9]+\.[0-9]+)\b`),
	}

	for _, pattern := range versionPatterns {
		matches := pattern.FindSubmatch(content)
		if len(matches) > 1 {
			return string(matches[1])
		}
	}

	return ""
}

// searchForStringsInFile scans a file for specific string patterns
func searchForStringsInFile(filePath string, patterns []*regexp.Regexp) map[string]string {
	results := make(map[string]string)

	file, err := os.Open(filePath)
	if err != nil {
		return results
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 64*1024), 1024*1024) // Increase buffer size

	for scanner.Scan() {
		line := scanner.Bytes()

		for i, pattern := range patterns {
			matches := pattern.FindSubmatch(line)
			if len(matches) > 1 {
				// Use pattern index as key if not provided
				key := pattern.String()
				if i < len(patterns) {
					key = strconv.Itoa(i)
				}
				results[key] = string(matches[1])
			}
		}
	}

	return results
}

// detectTextEncoding tries to detect the text encoding of a file
func detectTextEncoding(data []byte) string {
	// Check for UTF-8 BOM
	if len(data) >= 3 && data[0] == 0xEF && data[1] == 0xBB && data[2] == 0xBF {
		return "UTF-8 with BOM"
	}

	// Check for UTF-16 LE BOM
	if len(data) >= 2 && data[0] == 0xFF && data[1] == 0xFE {
		return "UTF-16 LE"
	}

	// Check for UTF-16 BE BOM
	if len(data) >= 2 && data[0] == 0xFE && data[1] == 0xFF {
		return "UTF-16 BE"
	}

	// Check for UTF-32 LE BOM
	if len(data) >= 4 && data[0] == 0xFF && data[1] == 0xFE && data[2] == 0x00 && data[3] == 0x00 {
		return "UTF-32 LE"
	}

	// Check for UTF-32 BE BOM
	if len(data) >= 4 && data[0] == 0x00 && data[1] == 0x00 && data[2] == 0xFE && data[3] == 0xFF {
		return "UTF-32 BE"
	}

	// If no BOM is detected but content is valid UTF-8, return UTF-8
	if utf8.Valid(data) {
		return "UTF-8"
	}

	// Check if it might be UTF-16 LE (even number of bytes, reasonable distribution)
	if len(data)%2 == 0 && len(data) > 4 {
		// Check for a pattern of alternating null bytes that suggests UTF-16 LE
		nullPattern := true
		for i := 0; i < min(len(data), 100); i += 2 {
			if data[i+1] != 0x00 {
				nullPattern = false
				break
			}
		}
		if nullPattern {
			return "UTF-16 LE (no BOM)"
		}
	}

	// Check if it might be UTF-16 BE
	if len(data)%2 == 0 && len(data) > 4 {
		// Check for a pattern of alternating null bytes that suggests UTF-16 BE
		nullPattern := true
		for i := 0; i < min(len(data), 100); i += 2 {
			if data[i] != 0x00 {
				nullPattern = false
				break
			}
		}
		if nullPattern {
			return "UTF-16 BE (no BOM)"
		}
	}

	// Default to ASCII/binary if we can't determine encoding
	return "ASCII/binary"
}

// detectExecutableBits checks if a file has executable permissions
func detectExecutableBits(filePath string) bool {
	info, err := os.Stat(filePath)
	if err != nil {
		return false
	}

	// Check if the file has executable bits set
	return info.Mode()&0111 != 0
}

// detectFileFormat tries to determine the format of a file based on content
func detectFileFormat(filePath string) (string, float64) {
	// Read the first few bytes of the file
	data, err := readFileSample(filePath, 8192)
	if err != nil {
		return "unknown", 0.0
	}

	// Format detection based on magic numbers/signatures
	signatures := []struct {
		format     string
		magic      []byte
		offset     int
		confidence float64
	}{
		{"elf", []byte{0x7F, 'E', 'L', 'F'}, 0, 0.9},
		{"pe/exe", []byte{0x4D, 0x5A}, 0, 0.9},
		{"zip", []byte{0x50, 0x4B, 0x03, 0x04}, 0, 0.9},
		{"jar/zip", []byte{0x50, 0x4B, 0x03, 0x04}, 0, 0.9},
		{"gzip", []byte{0x1F, 0x8B}, 0, 0.9},
		{"bzip2", []byte{0x42, 0x5A, 0x68}, 0, 0.9},
		{"7zip", []byte{0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C}, 0, 0.9},
		{"pdf", []byte{0x25, 0x50, 0x44, 0x46}, 0, 0.9},
		{"jpeg", []byte{0xFF, 0xD8, 0xFF}, 0, 0.9},
		{"png", []byte{0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A}, 0, 0.9},
		{"gif", []byte{0x47, 0x49, 0x46, 0x38}, 0, 0.9},
		{"ogg", []byte{0x4F, 0x67, 0x67, 0x53}, 0, 0.9},
		{"mp3", []byte{0x49, 0x44, 0x33}, 0, 0.8},
		{"mp4", []byte{0x00, 0x00, 0x00, 0x18, 0x66, 0x74, 0x79, 0x70}, 4, 0.8},
		{"ico", []byte{0x00, 0x00, 0x01, 0x00}, 0, 0.9},
		{"rpm", []byte{0xED, 0xAB, 0xEE, 0xDB}, 0, 0.9},
		{"class", []byte{0xCA, 0xFE, 0xBA, 0xBE}, 0, 0.9},
		{"deb", []byte{0x21, 0x3C, 0x61, 0x72, 0x63, 0x68, 0x3E}, 0, 0.9},
	}

	for _, sig := range signatures {
		if len(data) >= sig.offset+len(sig.magic) {
			if bytes.Equal(data[sig.offset:sig.offset+len(sig.magic)], sig.magic) {
				return sig.format, sig.confidence
			}
		}
	}

	// Check for text files
	isText, _ := isTextFile(filePath)
	if isText {
		// Try to identify specific text formats
		if len(data) >= 5 && bytes.Equal(data[0:5], []byte("<?xml")) {
			return "xml", 0.8
		}
		if len(data) >= 5 && bytes.Equal(data[0:5], []byte("<!DOC")) {
			return "html", 0.8
		}
		if bytes.Contains(data, []byte("<?php")) {
			return "php", 0.8
		}
		if bytes.Contains(data, []byte("#!/bin/sh")) || bytes.Contains(data, []byte("#!/bin/bash")) {
			return "shell-script", 0.8
		}
		if strings.HasSuffix(filePath, ".py") || bytes.Contains(data, []byte("#!/usr/bin/python")) {
			return "python-script", 0.8
		}

		return "text", 0.7
	}

	// If nothing matches, check if it's a binary file
	return "binary", 0.3
}

// extractStringsFromBinary extracts printable strings from a binary file
func extractStringsFromBinary(filePath string) ([]string, error) {
	// Read the file
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, err
	}

	// Extract strings (4 or more printable characters)
	var results []string
	current := make([]byte, 0, 1024)

	for _, b := range data {
		// Check if byte is a printable ASCII character
		if b >= 32 && b <= 126 {
			current = append(current, b)
		} else {
			// If we have a string of sufficient length, save it
			if len(current) >= 4 {
				results = append(results, string(current))
			}
			current = current[:0] // Reset buffer
		}
	}

	// Check final buffer
	if len(current) >= 4 {
		results = append(results, string(current))
	}

	return results, nil
}

// detectInstallStrings searches for installer-related strings
func detectInstallStrings(filePath string) (bool, []string) {
	// Get strings from the file
	extractedStrings, err := extractStringsFromBinary(filePath)
	if err != nil {
		return false, nil
	}

	// Installer-related keywords
	installerKeywords := []string{
		"install", "setup", "wizard", "uninstall", "update", "upgrade",
		"registry", "component", "extract", "deploy", "configuration",
	}

	matches := make([]string, 0)

	// Search for installer-related strings
	for _, s := range extractedStrings {
		lowerS := strings.ToLower(s)
		for _, keyword := range installerKeywords {
			if strings.Contains(lowerS, keyword) {
				matches = append(matches, s)
				break
			}
		}
	}

	return len(matches) > 0, matches
}
