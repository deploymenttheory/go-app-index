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
)

const (
	dmgMagic      = 0x6B6F6C79 // "koly" magic number in big-endian
	dmgHeaderSize = 512
	sectorSize    = 512
)

// ref: https://newosxbook.com/DMG.html

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

func computeFileHash(file *os.File) string {
	hash := sha256.New()
	file.Seek(0, io.SeekStart)
	if _, err := io.Copy(hash, file); err != nil {
		logger.Errorf("Failed to compute hash, error: %v", err)
	}
	return fmt.Sprintf("%x", hash.Sum(nil))
}

func decompressChunk(file *os.File, chunk blkxChunk, output io.Writer) error {
	file.Seek(int64(chunk.CompressedOffset), io.SeekStart)
	reader := io.LimitReader(file, int64(chunk.CompressedLength))

	var err error
	switch chunk.Type {
	case 0x80000005:
		zr, err := zlib.NewReader(reader)
		if err != nil {
			return err
		}
		defer zr.Close()
		_, err = io.Copy(output, zr)
	case 0x80000006:
		bzr := bzip2.NewReader(reader)
		_, err = io.Copy(output, bzr)
	case 0x80000007:
		data, err := io.ReadAll(reader)
		if err != nil {
			return err
		}
		decompressed := lzfse.DecodeBuffer(data)
		_, err = output.Write(decompressed)
	default:
		return errors.New("unsupported compression type")
	}
	return err
}
