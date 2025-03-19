package dmg

import (
	"fmt"
	"strings"
)

// Checksum represents a checksum in a DMG file
type Checksum struct {
	Type    uint32
	NumBits uint32
	Data    [ChecksumSizeMax]byte
}

// Parse parses a checksum from binary data
func (c *Checksum) Parse(data []byte) {
	c.Type = GetBe32(data, 0)
	c.NumBits = GetBe32(data, 4)
	copy(c.Data[:], data[8:8+ChecksumSizeMax])
}

// IsCrc32 returns whether this checksum is a CRC32 checksum
func (c *Checksum) IsCrc32() bool {
	return c.Type == ChecksumTypeCRC && c.NumBits == 32
}

// GetCrc32 returns the CRC32 value from the checksum data
func (c *Checksum) GetCrc32() uint32 {
	return GetBe32(c.Data[:], 0)
}

// PrintType returns a string representation of the checksum type
func (c *Checksum) PrintType() string {
	if c.NumBits == 0 {
		return ""
	}

	if c.IsCrc32() {
		return "CRC"
	}

	return fmt.Sprintf("Checksum%d-%d", c.Type, c.NumBits)
}

// Format returns a string representation of the checksum value
func (c *Checksum) Format() string {
	if c.NumBits == 0 {
		return ""
	}

	// Calculate how many bytes we need to represent the bits
	numBytes := (c.NumBits + 7) >> 3

	// Limit to maximum buffer size
	if numBytes > ChecksumSizeMax {
		numBytes = ChecksumSizeMax
	}

	if numBytes <= 8 {
		return ConvertDataToHexUpper(c.Data[:numBytes])
	}

	return ConvertDataToHexLower(c.Data[:numBytes])
}

// PrintWithName returns a string representation of the checksum with its type
func (c *Checksum) PrintWithName() string {
	if c.NumBits == 0 {
		return ""
	}

	typeName := c.PrintType()
	value := c.Format()

	return fmt.Sprintf("%s: %s", typeName, value)
}

// AddToComment adds the checksum information to a comment string
func (c *Checksum) AddToComment(comment *strings.Builder, name string) {
	formatted := c.PrintWithName()
	if formatted != "" {
		AddToCommentProp(comment, name, formatted)
	}
}

// AddToCommentProp adds a property to a comment string
func AddToCommentProp(s *strings.Builder, name, val string) {
	s.WriteString(name)
	s.WriteString(": ")
	s.WriteString(val)
	s.WriteString("\n")
}

// AddToCommentUInt64 adds a uint64 property to a comment string
func AddToCommentUInt64(s *strings.Builder, v uint64, name string) {
	s.WriteString(name)
	s.WriteString(": ")
	s.WriteString(fmt.Sprintf("%d", v))
	s.WriteString("\n")
}
