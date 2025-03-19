package dmg

import (
	"fmt"
	"strings"
)

// ForkPair represents a fork in a DMG file with offset and length
type ForkPair struct {
	Offset uint64
	Len    uint64
}

// Parse parses a ForkPair from binary data
// The data pointer is assumed to be aligned for 8-bytes
func (f *ForkPair) Parse(data []byte) {
	f.Offset = GetBe64a(data, 0)
	f.Len = GetBe64a(data, 8)
}

// GetEndPos calculates the end position of the fork
func (f *ForkPair) GetEndPos() (uint64, bool) {
	endPos := f.Offset + f.Len
	// Check for overflow
	return endPos, endPos >= f.Offset
}

// UpdateTop updates the top position if the fork extends beyond it
func (f *ForkPair) UpdateTop(limit uint64, top *uint64) bool {
	if f.Offset > limit || f.Len > limit-f.Offset {
		return false
	}

	endPos := f.Offset + f.Len
	if *top <= endPos {
		*top = endPos
	}

	return true
}

// Print adds the fork information to a string builder
func (f *ForkPair) Print(s *strings.Builder, name string) {
	if f.Offset != 0 || f.Len != 0 {
		s.WriteString(name)
		s.WriteString("-offset: ")
		s.WriteString(fmt.Sprintf("%d", f.Offset))
		s.WriteString("\n")

		s.WriteString(name)
		s.WriteString("-length: ")
		s.WriteString(fmt.Sprintf("%d", f.Len))
		s.WriteString("\n")
	}
}
