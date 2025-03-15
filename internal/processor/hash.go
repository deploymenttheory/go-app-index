package processor

import (
	"fmt"
	"io"
	"net/url"
	"os"

	"golang.org/x/crypto/sha3"
)

// generateSHA3Hash generates a SHA3-256 hash for a file
func generateSHA3Hash(filePath string) (string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return "", fmt.Errorf("failed to open file: %w", err)
	}
	defer file.Close()

	h := sha3.New256()
	if _, err := io.Copy(h, file); err != nil {
		return "", fmt.Errorf("failed to read file: %w", err)
	}

	return fmt.Sprintf("%x", h.Sum(nil)), nil
}

// extractDomain extracts the domain from a URL
func extractDomain(urlStr string) (string, error) {
	parsedURL, err := url.Parse(urlStr)
	if err != nil {
		return "", err
	}

	return parsedURL.Hostname(), nil
}
