package fileanalyzer

import (
	"bytes"
	"compress/bzip2"
	"compress/zlib"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/deploymenttheory/go-app-index/internal/logger"
	"howett.net/plist"
)

const (
	dmgMagic      = 0x6B6F6C79 // "koly" magic number in big-endian
	dmgHeaderSize = 512
	sectorSize    = 512
)

type dmgHeader struct {
	Signature        [4]byte   // Magic ("koly")
	Version          uint32    // Current version is 4
	HeaderSize       uint32    // Always 512
	Flags            uint32    // Various flags
	RunningDataFork  uint64    // Running data fork offset
	DataForkOffset   uint64    // Data fork offset
	DataForkLength   uint64    // Data fork size
	RsrcForkOffset   uint64    // Resource fork offset
	RsrcForkLength   uint64    // Resource fork size
	SegmentNumber    uint32    // Usually 1
	SegmentCount     uint32    // Usually 1
	SegmentID        [16]byte  // UUID
	DataChecksumType uint32    // Data fork checksum type
	DataChecksumSize uint32    // Data checksum size
	DataChecksum     [128]byte // Up to 128-bytes of checksum
	XMLOffset        uint64    // Offset of XML plist
	XMLLength        uint64    // Length of XML plist
	Reserved         [120]byte // Reserved space
	ChecksumType     uint32    // Master checksum type
	ChecksumSize     uint32    // Master checksum size
	Checksum         [128]byte // Master checksum
	ImageVariant     uint32    // Commonly 1
	SectorCount      uint64    // Size when expanded in sectors
	Reserved2        [12]byte  // Reserved fields
}

type blkxChunk struct {
	Type             uint32 // Compression type
	Reserved         uint32 // Reserved
	Comment          uint32
	SectorNumber     uint64 // Starting sector
	SectorCount      uint64 // Number of sectors
	CompressedOffset uint64 // Offset in the compressed data
	CompressedLength uint64 // Length of the compressed data
}

// Update the dmgPlist struct
type dmgPlist struct {
	ResourceFork resourceFork `plist:"resource-fork"`
}

type resourceFork struct {
	Blkx []blkxElement `plist:"blkx"`
	Plst interface{}   `plist:"plst"` // Not using this currently
}

type blkxElement struct {
	ID         string      `plist:"ID"`
	Name       string      `plist:"Name"`
	Attributes interface{} `plist:"Attributes"`
	CFName     string      `plist:"CFName,omitempty"`
	Data       []byte      `plist:"Data"` // Binary data containing chunks
}

// A header at the beginning of the blkx Data field
type blkxHeader struct {
	Signature   [4]byte // Should be "mish"
	Version     uint32  // Version of the format
	SectorCount uint32  // Number of sectors
	Reserved1   uint32  // Reserved
	Reserved2   uint32  // Reserved
	ChunkCount  uint32  // Number of chunks
	// More fields may follow but we only need these for parsing
}

func analyzeDMG(filePath string) (*Result, error) {
	logger.Infof("Analyzing DMG: %s", filePath)

	file, err := os.Open(filePath)
	if err != nil {
		logger.Errorf("Failed to open DMG file: %s, error: %v", filePath, err)
		return nil, err
	}
	defer file.Close()

	fileInfo, err := file.Stat()
	if err != nil {
		logger.Errorf("Failed to stat DMG file: %s, error: %v", filePath, err)
		return nil, err
	}

	if fileInfo.Size() < dmgHeaderSize {
		logger.Errorf("File too small to be a valid DMG: %s", filePath)
		return nil, errors.New("invalid dmg file")
	}

	headerOffset := fileInfo.Size() - dmgHeaderSize
	if _, err := file.Seek(headerOffset, io.SeekStart); err != nil {
		logger.Errorf("Failed to seek to koly header in %s, error: %v", filePath, err)
		return nil, err
	}

	var header dmgHeader
	if err := binary.Read(file, binary.BigEndian, &header); err != nil {
		logger.Errorf("Failed to read koly header: %s, error: %v", filePath, err)
		return nil, err
	}

	if string(header.Signature[:]) != "koly" {
		logger.Errorf("Invalid DMG magic signature in %s", filePath)
		return nil, errors.New("invalid dmg signature")
	}

	logger.Debugf("Parsed DMG header: %+v", header)

	// Extract the XML Property List (Plist)
	plistData, err := extractPlist(file, header)
	if err != nil {
		logger.Errorf("Failed to extract DMG XML plist: %s", err)
		return nil, err
	}

	// Parse blkx table
	blkxTable, err := parseBlkxTable(plistData)
	if err != nil {
		logger.Errorf("Failed to parse blkx table: %s", err)
		return nil, err
	}

	// Extract the DMG contents
	outputPath := filePath + ".extracted"
	err = extractDMG(file, blkxTable, outputPath)
	if err != nil {
		logger.Errorf("Failed to extract DMG contents: %s", err)
		return nil, err
	}

	metadata := map[string]interface{}{
		"file_name":        filepath.Base(filePath),
		"sha256":           computeFileHash(file),
		"xml_offset":       header.XMLOffset,
		"xml_length":       header.XMLLength,
		"data_fork_offset": header.DataForkOffset,
		"data_fork_length": header.DataForkLength,
		"resource_fork":    header.RsrcForkLength,
		"sector_count":     header.SectorCount,
	}

	logger.Infof("Extracted DMG metadata: %+v", metadata)

	return &Result{
		FileType:    "dmg",
		Platform:    "macos",
		Confidence:  0.95,
		IsInstaller: true,
		Metadata:    metadata,
		AnalyzedAt:  timeNow(),
	}, nil
}

func extractPlist(file *os.File, header dmgHeader) ([]byte, error) {
	file.Seek(int64(header.XMLOffset), io.SeekStart)
	plistData := make([]byte, header.XMLLength)
	_, err := file.Read(plistData)
	if err != nil {
		return nil, fmt.Errorf("failed to read XML plist: %w", err)
	}
	return plistData, nil
}

func parseBlkxTable(plistData []byte) (*resourceFork, error) {
	debugPlistStructure(plistData)

	var dmgPlist dmgPlist
	_, err := plist.Unmarshal(plistData, &dmgPlist)
	if err != nil {
		return nil, fmt.Errorf("failed to parse DMG property list: %w", err)
	}

	if len(dmgPlist.ResourceFork.Blkx) == 0 {
		return nil, errors.New("blkx table not found in DMG plist")
	}

	return &dmgPlist.ResourceFork, nil
}

func debugPlistStructure(plistData []byte) {
	var raw interface{}
	_, err := plist.Unmarshal(plistData, &raw)
	if err != nil {
		logger.Errorf("Failed to unmarshal plist for debugging: %v", err)
		return
	}

	// Log the type and structure
	logger.Debugf("Plist type: %T", raw)

	// Try to print a summary of the structure
	switch v := raw.(type) {
	case map[string]interface{}:
		keys := make([]string, 0, len(v))
		for k := range v {
			keys = append(keys, k)
		}
		logger.Debugf("Plist is a dictionary with keys: %v", keys)

		// If there's a resource-fork, examine it more closely
		if rf, ok := v["resource-fork"]; ok {
			logger.Debugf("Resource-fork type: %T", rf)
			if rfMap, isMap := rf.(map[string]interface{}); isMap {
				rfKeys := make([]string, 0, len(rfMap))
				for k := range rfMap {
					rfKeys = append(rfKeys, k)
				}
				logger.Debugf("Resource-fork keys: %v", rfKeys)

				// Look for blkx data
				if blkx, hasBlkx := rfMap["blkx"]; hasBlkx {
					logger.Debugf("Blkx type: %T", blkx)
					if blkxArr, isArray := blkx.([]interface{}); isArray && len(blkxArr) > 0 {
						logger.Debugf("First blkx element type: %T", blkxArr[0])
						if firstElem, isMap := blkxArr[0].(map[string]interface{}); isMap {
							elemKeys := make([]string, 0, len(firstElem))
							for k := range firstElem {
								elemKeys = append(elemKeys, k)
							}
							logger.Debugf("First blkx element keys: %v", elemKeys)
						}
					}
				}
			}
		}
	case []interface{}:
		logger.Debugf("Plist is an array with %d elements", len(v))
	default:
		logger.Debugf("Plist is of unexpected type")
	}
}

func extractDMG(file *os.File, resourceFork *resourceFork, outputPath string) error {
	outputFile, err := os.Create(outputPath)
	if err != nil {
		return fmt.Errorf("failed to create output file: %w", err)
	}
	defer outputFile.Close()

	// Find the main disk image partition (typically Apple_HFS)
	var mainPartition *blkxElement
	for _, element := range resourceFork.Blkx {
		if strings.Contains(element.Name, "Apple_HFS") ||
			strings.Contains(element.Name, "disk image") {
			mainPartition = &element
			break
		}
	}

	if mainPartition == nil {
		return fmt.Errorf("no main partition found in DMG")
	}

	logger.Infof("Found main partition: %s", mainPartition.Name)

	// Parse the blkx data to extract chunks
	chunks, err := parseBlkxData(mainPartition.Data)
	if err != nil {
		return fmt.Errorf("failed to parse blkx data: %w", err)
	}

	logger.Infof("Extracted %d chunks from partition", len(chunks))

	// Process each chunk
	for i, chunk := range chunks {
		logger.Debugf("Processing chunk %d: type=0x%08x, sectors=%d, offset=%d, length=%d",
			i, chunk.Type, chunk.SectorCount, chunk.CompressedOffset, chunk.CompressedLength)

		// Skip chunks with zero sectors
		if chunk.SectorCount == 0 {
			continue
		}

		// Decompress the chunk
		if err := decompressChunk(file, chunk, outputFile); err != nil {
			logger.Warningf("Failed to decompress chunk %d: %v", i, err)
			// Continue with other chunks instead of failing
			continue
		}
	}

	logger.Infof("DMG extraction complete: %s", outputPath)
	return nil
}

// Update the parseBlkxData function to better handle DMG data format
func parseBlkxData(data []byte) ([]blkxChunk, error) {
	if len(data) < 24 { // Need at least room for the header
		return nil, fmt.Errorf("data too short for blkx header")
	}

	// Check signature - should be "mish"
	if string(data[0:4]) != "mish" {
		return nil, fmt.Errorf("invalid blkx signature: %s", string(data[0:4]))
	}

	// Log the first few bytes to help debug
	logger.Debugf("First 32 bytes of blkx data: %v", data[0:32])

	// The format might be different than expected
	// Version might be at a different offset
	version := binary.BigEndian.Uint32(data[4:8])

	// The number of entries is typically much smaller than the sector count
	// Try to determine a reasonable number of chunks
	var numChunks uint32

	// Try different approaches
	if version == 1 {
		// For version 1, try reading at offset 12
		sectorCount := binary.BigEndian.Uint32(data[8:12])
		logger.Debugf("Read sector count: %d", sectorCount)

		// The number of chunks is typically much smaller
		// Let's make a conservative estimate based on the data size
		maxChunks := (len(data) - 24) / 40 // Each chunk is typically 40 bytes

		// Use a reasonable value
		numChunks = uint32(maxChunks)
		logger.Debugf("Calculated maximum chunks: %d", numChunks)
	} else {
		// Default approach - assume the number of chunks is at offset 20
		// but verify it's a reasonable number
		possibleChunks := binary.BigEndian.Uint32(data[20:24])

		// Check if the number is reasonable
		maxPossible := (len(data) - 24) / 40
		if int(possibleChunks) > maxPossible || possibleChunks > 1000 { // Sanity check
			logger.Warningf("Unreasonable chunk count %d, limiting to %d", possibleChunks, maxPossible)
			numChunks = uint32(maxPossible)
		} else {
			numChunks = possibleChunks
		}
	}

	// If we still have no chunks, try to parse at least one
	if numChunks == 0 && len(data) >= 64 { // 24 + 40
		numChunks = 1
	}

	logger.Debugf("Processing %d chunks", numChunks)

	// Calculate where chunks start - typically right after the header
	chunkDataStart := 24 // Size of the basic header

	// Make sure we have enough data for all chunks
	if len(data) < chunkDataStart+int(numChunks*40) {
		return nil, fmt.Errorf("data too short for %d chunks", numChunks)
	}

	// Parse each chunk
	chunks := make([]blkxChunk, numChunks)
	for i := uint32(0); i < numChunks; i++ {
		offset := chunkDataStart + int(i*40)

		// Ensure we have enough data for this chunk
		if offset+40 > len(data) {
			// We've reached the end of the data
			return chunks[:i], nil
		}

		chunk := blkxChunk{
			Type:             binary.BigEndian.Uint32(data[offset : offset+4]),
			Reserved:         binary.BigEndian.Uint32(data[offset+4 : offset+8]),
			SectorNumber:     binary.BigEndian.Uint64(data[offset+8 : offset+16]),
			SectorCount:      binary.BigEndian.Uint64(data[offset+16 : offset+24]),
			CompressedOffset: binary.BigEndian.Uint64(data[offset+24 : offset+32]),
			CompressedLength: binary.BigEndian.Uint64(data[offset+32 : offset+40]),
		}

		logger.Debugf("Chunk %d: type=0x%x, sectors=%d, offset=%d, length=%d",
			i, chunk.Type, chunk.SectorCount, chunk.CompressedOffset, chunk.CompressedLength)

		chunks[i] = chunk
	}

	return chunks, nil
}

func decompressChunk(file *os.File, chunk blkxChunk, output io.Writer) error {
	// Special case: if type is 0 or 1, it's raw/empty data
	if chunk.Type == 0 || chunk.Type == 1 {
		// For empty data, just write zeroes
		zeros := make([]byte, chunk.SectorCount*512) // 512 bytes per sector
		_, err := output.Write(zeros)
		return err
	}

	// Seek to the offset in the file
	if _, err := file.Seek(int64(chunk.CompressedOffset), io.SeekStart); err != nil {
		return fmt.Errorf("failed to seek to chunk offset: %w", err)
	}

	// Read the compressed data
	compressedData := make([]byte, chunk.CompressedLength)
	if _, err := io.ReadFull(file, compressedData); err != nil {
		return fmt.Errorf("failed to read compressed data: %w", err)
	}

	// Decompress based on type
	switch chunk.Type {
	case 0x80000005: // zlib
		reader, err := zlib.NewReader(bytes.NewReader(compressedData))
		if err != nil {
			return fmt.Errorf("failed to create zlib reader: %w", err)
		}
		defer reader.Close()

		if _, err := io.Copy(output, reader); err != nil {
			return fmt.Errorf("failed to decompress zlib data: %w", err)
		}

	case 0x80000006: // bzip2
		reader := bzip2.NewReader(bytes.NewReader(compressedData))
		if _, err := io.Copy(output, reader); err != nil {
			return fmt.Errorf("failed to decompress bzip2 data: %w", err)
		}

	case 0x00000001: // raw/uncompressed
		// Just copy the data as-is
		if _, err := output.Write(compressedData); err != nil {
			return fmt.Errorf("failed to write raw data: %w", err)
		}

	// Add more decompression types as needed

	default:
		return fmt.Errorf("unsupported compression type: 0x%08x", chunk.Type)
	}

	return nil
}

func computeFileHash(file *os.File) string {
	hash := sha256.New()
	file.Seek(0, io.SeekStart)
	if _, err := io.Copy(hash, file); err != nil {
		logger.Errorf("Failed to compute hash, error: %v", err)
	}
	return fmt.Sprintf("%x", hash.Sum(nil))
}
