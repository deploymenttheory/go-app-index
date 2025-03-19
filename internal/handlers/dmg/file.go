package dmg

import (
	"errors"
	"strings"
)

// File represents a file in a DMG archive
type File struct {
	Size              uint64
	Blocks            []Block
	PackSize          uint64
	StartPackPos      uint64
	BlockSizeMAX      uint64
	StartUnpackSector uint64 // unpack sector position of this file from all files
	NumUnpackSectors  uint64
	Descriptor        int32
	IsCorrect         bool
	FullFileChecksum  bool
	Name              string
	Checksum          Checksum
}

// NewFile creates a new File with default values
func NewFile() *File {
	return &File{
		Size:              0,
		PackSize:          0,
		StartPackPos:      0,
		BlockSizeMAX:      0,
		StartUnpackSector: 0,
		NumUnpackSectors:  0,
		Descriptor:        0,
		IsCorrect:         false,
		FullFileChecksum:  false,
	}
}

// GetUnpackSizeOfBlock returns the unpacked size of a block
func (f *File) GetUnpackSizeOfBlock(blockIndex int) uint64 {
	if blockIndex == len(f.Blocks)-1 {
		return f.Size - f.Blocks[blockIndex].UnpPos
	}
	return f.Blocks[blockIndex+1].UnpPos - f.Blocks[blockIndex].UnpPos
}

// Parse parses a File from binary data
func (f *File) Parse(data []byte) error {
	// File was initialized to default values
	const headSize = 0xCC
	if len(data) < headSize {
		return errors.New("data too small")
	}

	// Check for "mish" signature
	if GetBe32(data, 0) != 0x6D697368 {
		return errors.New("invalid signature")
	}

	// Check version
	if GetBe32(data, 4) != 1 {
		return errors.New("invalid version")
	}

	f.StartUnpackSector = GetBe64(data, 8)
	f.NumUnpackSectors = GetBe64(data, 0x10)
	f.StartPackPos = GetBe64(data, 0x18)
	f.Descriptor = int32(GetBe32(data, 0x24))

	f.Checksum.Parse(data[0x40:])

	numBlocks := GetBe32(data, 0xC8)
	const recordSize = 40
	if uint64(numBlocks)*uint64(recordSize)+uint64(headSize) != uint64(len(data)) {
		return errors.New("invalid size")
	}

	f.Blocks = make([]Block, 0, numBlocks)
	f.FullFileChecksum = true

	p := headSize
	for i := uint32(0); i < numBlocks; i++ {
		b := Block{
			Type: GetBe32(data, p),
		}

		// Calculate unpacked position
		sectorNum := GetBe64(data, p+0x08)
		if sectorNum >= SectorNumberLimit {
			return nil // Ignore this error and continue
		}
		b.UnpPos = sectorNum << 9

		// Calculate unpacked size (not stored directly in the block)
		unpSectors := GetBe64(data, p+0x10)
		if unpSectors >= SectorNumberLimit {
			return nil // Ignore this error and continue
		}
		unpSize := unpSectors << 9

		newSize := b.UnpPos + unpSize
		if newSize >= (uint64(1) << 63) {
			return nil // Ignore this error and continue
		}

		b.PackPos = GetBe64(data, p+0x18)
		b.PackSize = GetBe64(data, p+0x20)

		if b.UnpPos != f.Size {
			return nil // Ignore this error and continue
		}

		// Skip comment blocks
		if b.Type == MethodComment {
			p += recordSize
			continue
		}

		// End block marks the end of the blocks
		if b.Type == MethodEnd {
			break
		}

		// We add only blocks that have non-empty unpacked data
		if unpSize != 0 {
			const maxPos = uint64(1) << 63
			if b.PackPos >= maxPos || b.PackSize >= maxPos-b.PackPos {
				return nil // Ignore this error and continue
			}

			// Update max block size
			if b.IsClusteredMethod() && f.BlockSizeMAX < unpSize {
				f.BlockSizeMAX = unpSize
			}

			f.PackSize += b.PackSize
			if !b.NeedCrc() {
				f.FullFileChecksum = false
			}

			f.Blocks = append(f.Blocks, b)
			f.Size = newSize
		}

		p += recordSize
	}

	// If the calculated sectors match the header sectors, the file is correct
	if (f.Size >> 9) == f.NumUnpackSectors {
		f.IsCorrect = true
	}

	return nil
}

// AppleName represents a known Apple filesystem or partition type
type AppleName struct {
	IsFs      bool
	Ext       string
	AppleName string
}

// Known Apple partition and filesystem types
var AppleNames = []AppleName{
	{true, "hfs", "Apple_HFS"},
	{true, "hfsx", "Apple_HFSX"},
	{true, "ufs", "Apple_UFS"},
	{true, "apfs", "Apple_APFS"},
	{true, "iso", "Apple_ISO"},

	// efi_sys partition is FAT32, but it's not main file. So we use IsFs = false
	{false, "efi_sys", "C12A7328-F81F-11D2-BA4B-00A0C93EC93B"},

	{false, "free", "Apple_Free"},
	{false, "ddm", "DDM"},
	{false, "", "Apple_partition_map"},
	{false, "", " GPT "},
	{false, "", "MBR"},
	{false, "", "Driver"},
	{false, "", "Patches"},
}

// FindAppleFSExt finds the file extension for an Apple filesystem name
func FindAppleFSExt(name string) string {
	for _, a := range AppleNames {
		if a.Ext != "" && name == a.AppleName {
			return a.Ext
		}
	}
	return ""
}

// IsAppleFSOrUnknown checks if a name is an Apple filesystem or unknown
func IsAppleFSOrUnknown(name string) bool {
	for _, a := range AppleNames {
		if strings.Contains(name, a.AppleName) {
			return a.IsFs
		}
	}
	// Default to true for unknown names
	return true
}
