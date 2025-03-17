package fileanalyzer

import (
	"compress/bzip2"
	"compress/zlib"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/blacktop/lzfse-cgo"
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
	Type             uint32
	Comment          uint32
	SectorNumber     uint64
	SectorCount      uint64
	CompressedOffset uint64
	CompressedLength uint64
}

type dmgPlist struct {
	BLKXTables []blkxTable `plist:"resource-fork"`
}

type blkxTable struct {
	Chunks []blkxChunk `plist:"blkx"`
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

func parseBlkxTable(plistData []byte) (*blkxTable, error) {
	var dmgPlist dmgPlist
	_, err := plist.Unmarshal(plistData, &dmgPlist)
	if err != nil {
		return nil, fmt.Errorf("failed to parse DMG property list: %w", err)
	}

	if len(dmgPlist.BLKXTables) == 0 {
		return nil, errors.New("blkx table not found in DMG plist")
	}

	// Assuming we want the first BLKX table
	return &dmgPlist.BLKXTables[0], nil
}

func extractDMG(file *os.File, blkxTable *blkxTable, outputPath string) error {
	outputFile, err := os.Create(outputPath)
	if err != nil {
		return fmt.Errorf("failed to create output file: %w", err)
	}
	defer outputFile.Close()

	for _, chunk := range blkxTable.Chunks {
		err := decompressChunk(file, chunk, outputFile)
		if err != nil {
			return fmt.Errorf("failed to decompress chunk: %w", err)
		}
	}
	logger.Infof("DMG extraction complete: %s", outputPath)
	return nil
}

func decompressChunk(file *os.File, chunk blkxChunk, output io.Writer) error {
	// Seek to the offset where the compressed data starts
	if _, err := file.Seek(int64(chunk.CompressedOffset), io.SeekStart); err != nil {
		return fmt.Errorf("failed to seek to chunk offset: %w", err)
	}

	// Limit reading to the compressed length
	reader := io.LimitReader(file, int64(chunk.CompressedLength))

	switch chunk.Type {
	case 0x80000005: // ZLIB
		zr, err := zlib.NewReader(reader)
		if err != nil {
			return fmt.Errorf("failed to create zlib reader: %w", err)
		}
		defer zr.Close()
		if _, err := io.Copy(output, zr); err != nil {
			return fmt.Errorf("failed to decompress zlib chunk: %w", err)
		}

	case 0x80000006: // BZIP2
		bzr := bzip2.NewReader(reader)
		if _, err := io.Copy(output, bzr); err != nil {
			return fmt.Errorf("failed to decompress bzip2 chunk: %w", err)
		}

	case 0x80000007: // LZFSE
		data, err := io.ReadAll(reader)
		if err != nil {
			return fmt.Errorf("failed to read LZFSE compressed data: %w", err)
		}
		decompressed := lzfse.DecodeBuffer(data)
		if decompressed == nil {
			return errors.New("failed to decode LZFSE data")
		}
		if _, err := output.Write(decompressed); err != nil {
			return fmt.Errorf("failed to write decompressed LZFSE data: %w", err)
		}

	default:
		return fmt.Errorf("unsupported compression type: 0x%x", chunk.Type)
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
