package dmg

import (
	"fmt"
	"strings"
)

// Block represents a data block in a DMG file
type Block struct {
	Type     uint32
	UnpPos   uint64
	PackPos  uint64
	PackSize uint64
}

// NeedCrc returns whether this block requires CRC calculation
func (b *Block) NeedCrc() bool {
	return b.Type != MethodZero2
}

// IsZeroMethod returns whether this block uses a zero method
func (b *Block) IsZeroMethod() bool {
	return (b.Type &^ MethodZero2) == 0
	// equivalent to: b.Type == MethodZero0 || b.Type == MethodZero2
}

// IsClusteredMethod returns whether this block uses a clustered method
func (b *Block) IsClusteredMethod() bool {
	// Most DMG files have non-fused COPY_METHOD blocks.
	// We don't exclude COPY_METHOD blocks when trying to detect size of cluster.
	return !b.IsZeroMethod() // Include COPY_METHOD blocks
}

// NeedAllocateBuffer returns whether this block needs a buffer to be allocated
func (b *Block) NeedAllocateBuffer() bool {
	// In Go, we need to make a direct decision rather than using preprocessor directives
	// For this implementation, we'll choose one approach:

	// Uncomment one of these based on your preference:
	// return !b.IsZeroMethod() // This includes COPY_METHOD blocks in caching
	return !b.IsZeroMethod() && b.Type != MethodCopy // This excludes COPY_METHOD blocks from caching
}

// Methods keeps track of unique block types
type Methods struct {
	Types []uint32
}

// Update adds the block types from a file to the methods list
func (m *Methods) Update(file *File) {
	for _, block := range file.Blocks {
		// Limit to 256 types
		if len(m.Types) >= 256 {
			break
		}

		m.AddToUniqueSorted(block.Type)
	}
}

// AddToUniqueSorted adds a type to the list if it's not already present
func (m *Methods) AddToUniqueSorted(typeVal uint32) {
	// Linear search since the list is small
	for _, t := range m.Types {
		if t == typeVal {
			return
		}
	}

	// Add the type and keep the list sorted
	m.Types = append(m.Types, typeVal)

	// Simple insertion sort
	for i := len(m.Types) - 1; i > 0; i-- {
		if m.Types[i] < m.Types[i-1] {
			m.Types[i], m.Types[i-1] = m.Types[i-1], m.Types[i]
		} else {
			break
		}
	}
}

// AddToString adds the methods list to a string
func (m *Methods) AddToString(s *strings.Builder) {
	for i, typeVal := range m.Types {
		if i > 0 {
			s.WriteString(" ")
		}

		var methodName string
		switch typeVal {
		case MethodZero0:
			methodName = "Zero0"
		case MethodZero2:
			methodName = "Zero2"
		case MethodCopy:
			methodName = "Copy"
		case MethodADC:
			methodName = "ADC"
		case MethodZLIB:
			methodName = "ZLIB"
		case MethodBZIP2:
			methodName = "BZip2"
		case MethodLZFSE:
			methodName = "LZFSE"
		case MethodXZ:
			methodName = "XZ"
		default:
			methodName = fmt.Sprintf("%x", typeVal)
		}

		s.WriteString(methodName)
	}
}
