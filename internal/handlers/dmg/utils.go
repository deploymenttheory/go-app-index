package dmg

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"hash/crc32"
	"strings"
)

// SizeTSize is platform-dependent: 4 for 32-bit, 8 for 64-bit
const SizeTSize = 8 // Assuming 64-bit platform

// GetBe16 reads a 16-bit big-endian value from data at the given offset
func GetBe16(data []byte, offset int) uint16 {
	return binary.BigEndian.Uint16(data[offset:])
}

// GetBe32 reads a 32-bit big-endian value from data at the given offset
func GetBe32(data []byte, offset int) uint32 {
	return binary.BigEndian.Uint32(data[offset:])
}

// GetBe64 reads a 64-bit big-endian value from data at the given offset
func GetBe64(data []byte, offset int) uint64 {
	return binary.BigEndian.Uint64(data[offset:])
}

// GetBe32a is an alias for GetBe32 for aligned data
func GetBe32a(data []byte, offset int) uint32 {
	return GetBe32(data, offset)
}

// GetBe64a is an alias for GetBe64 for aligned data
func GetBe64a(data []byte, offset int) uint64 {
	return GetBe64(data, offset)
}

// CrcInitVal is the initial value for CRC32 calculation
const CrcInitVal uint32 = 0xffffffff

// CrcUpdate updates a running CRC32 checksum with new data
func CrcUpdate(crc uint32, data []byte) uint32 {
	return crc32.Update(crc, crc32.IEEETable, data)
}

// CrcGetDigest returns the final CRC32 digest value
func CrcGetDigest(crc uint32) uint32 {
	return crc ^ 0xffffffff
}

// Base64ToBin decodes a base64 string to binary
func Base64ToBin(src string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(src)
}

// IsKoly checks if the given data matches the Koly signature
func IsKoly(data []byte) bool {
	return bytes.Equal(data[:len(KolySignature)], KolySignature)
}

// ConvertUInt32ToHex converts a uint32 to a hex string
func ConvertUInt32ToHex(val uint32) string {
	return fmt.Sprintf("%08x", val)
}

// ConvertDataToHexUpper converts binary data to uppercase hex string
func ConvertDataToHexUpper(data []byte) string {
	return strings.ToUpper(hex.EncodeToString(data))
}

// ConvertDataToHexLower converts binary data to lowercase hex string
func ConvertDataToHexLower(data []byte) string {
	return hex.EncodeToString(data)
}

// Min returns the minimum of two uint64 values
func Min(a, b uint64) uint64 {
	if a < b {
		return a
	}
	return b
}
