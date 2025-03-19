package dmg

// Constants for block methods
const (
	MethodZero0   uint32 = 0 // sparse
	MethodCopy    uint32 = 1
	MethodZero2   uint32 = 2 // sparse : without file CRC calculation
	MethodADC     uint32 = 0x80000004
	MethodZLIB    uint32 = 0x80000005
	MethodBZIP2   uint32 = 0x80000006
	MethodLZFSE   uint32 = 0x80000007
	MethodXZ      uint32 = 0x80000008
	MethodComment uint32 = 0x7FFFFFFE // used to comment "+beg" and "+end" in extra field
	MethodEnd     uint32 = 0xFFFFFFFF
)

// Constants for checksum types
const (
	ChecksumTypeCRC uint32 = 2
	ChecksumSizeMax        = 0x80
)

// Sector and size limits
const (
	SectorNumberLimit = uint64(1) << (63 - 9)
	SectorSize        = 512
)

// Buffer and cache limits
const (
	NumChunksMax = 128
	ChunkSizeMax = uint64(1) << 28 // 256MB

	// Fixed values for 64-bit systems
	ChunksTotalSizeMax = uint64(1) << 40         // 1TB, reasonable cache limit
	XMLSizeMax         = (uint64(1) << 31) - 256 // ~2GB, reasonable XML size limit

	ZeroBufSize = 1 << 14
)

// Other constants
const (
	KolyHeaderSize = 0x200
)

// KolySignature is the signature for a Koly header
var KolySignature = []byte{'k', 'o', 'l', 'y', 0, 0, 0, 4, 0, 0, 2, 0}
