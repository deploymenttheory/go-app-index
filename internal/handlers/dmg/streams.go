package dmg

import (
	"bytes"
	"errors"
	"io"
	"sync"
)

// LimitedReader wraps an io.Reader with a size limit
type LimitedReader struct {
	R      io.Reader
	N      uint64
	pos    uint64
	closed bool
}

// Read implements io.Reader interface
func (l *LimitedReader) Read(p []byte) (n int, err error) {
	if l.closed {
		return 0, errors.New("read from closed reader")
	}

	if l.pos >= l.N {
		return 0, io.EOF
	}

	if uint64(len(p)) > l.N-l.pos {
		p = p[:l.N-l.pos]
	}

	n, err = l.R.Read(p)
	l.pos += uint64(n)
	return
}

// Close implements io.Closer interface
func (l *LimitedReader) Close() error {
	l.closed = true
	if closer, ok := l.R.(io.Closer); ok {
		return closer.Close()
	}
	return nil
}

// OutStreamWithCRC wraps an io.Writer with CRC calculation
type OutStreamWithCRC struct {
	W       io.Writer
	crc     uint32
	enabled bool
}

// Write implements io.Writer interface
func (o *OutStreamWithCRC) Write(p []byte) (n int, err error) {
	if o.enabled {
		o.crc = CrcUpdate(o.crc, p)
	}
	return o.W.Write(p)
}

// Init initializes the CRC value
func (o *OutStreamWithCRC) Init(calcCRC bool) {
	o.crc = CrcInitVal
	o.enabled = calcCRC
}

// EnableCalc enables or disables CRC calculation
func (o *OutStreamWithCRC) EnableCalc(enabled bool) {
	o.enabled = enabled
}

// GetCRC returns the calculated CRC
func (o *OutStreamWithCRC) GetCRC() uint32 {
	return CrcGetDigest(o.crc)
}

// LimitedWriter wraps an io.Writer with a size limit
type LimitedWriter struct {
	W      io.Writer
	N      uint64
	pos    uint64
	closed bool
}

// Write implements io.Writer interface
func (l *LimitedWriter) Write(p []byte) (n int, err error) {
	if l.closed {
		return 0, errors.New("write to closed writer")
	}

	if l.pos >= l.N {
		return 0, io.ErrShortWrite
	}

	if uint64(len(p)) > l.N-l.pos {
		p = p[:l.N-l.pos]
	}

	n, err = l.W.Write(p)
	l.pos += uint64(n)
	return
}

// Close implements io.Closer interface
func (l *LimitedWriter) Close() error {
	l.closed = true
	if closer, ok := l.W.(io.Closer); ok {
		return closer.Close()
	}
	return nil
}

// GetRem returns the remaining bytes that can be written
func (l *LimitedWriter) GetRem() uint64 {
	if l.pos >= l.N {
		return 0
	}
	return l.N - l.pos
}

// IsFinishedOK returns true if all bytes have been written
func (l *LimitedWriter) IsFinishedOK() bool {
	return l.pos == l.N
}

// Chunk represents a cached chunk of a file
type Chunk struct {
	BlockIndex int
	AccessMark uint64
	Buf        []byte
	BufSize    uint64
}

// Free releases the memory used by the chunk
func (c *Chunk) Free() {
	c.Buf = nil
	c.BufSize = 0
}

// Alloc allocates memory for the chunk
func (c *Chunk) Alloc(size uint64) error {
	c.Buf = make([]byte, size)
	c.BufSize = size
	return nil
}

// InStream implements a reader for DMG files
type InStream struct {
	mutex           sync.Mutex
	errorMode       bool
	virtPos         uint64
	latestChunk     int
	latestBlock     int
	accessMark      uint64
	chunksTotalSize uint64
	chunks          []Chunk
	stream          io.ReadSeeker
	file            *File
	size            uint64
	startPos        uint64
	registry        *DecoderRegistry
}

// NewInStream creates a new InStream
func NewInStream(stream io.ReadSeeker, file *File, startPos uint64) *InStream {
	return &InStream{
		stream:      stream,
		file:        file,
		size:        file.Size,
		registry:    NewDecoderRegistry(),
		startPos:    startPos,
		latestChunk: -1,
		latestBlock: -1,
	}
}

// Read implements io.Reader interface
func (s *InStream) Read(p []byte) (n int, err error) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	if s.errorMode {
		return 0, errors.New("read in error mode")
	}

	if len(p) == 0 {
		return 0, nil
	}

	if s.virtPos >= s.size {
		return 0, io.EOF
	}

	// Adjust read size if necessary
	remain := s.size - s.virtPos
	toRead := uint64(len(p))
	if toRead > remain {
		toRead = remain
	}

	// Find which block contains the current position
	if s.latestBlock >= 0 {
		block := s.file.Blocks[s.latestBlock]
		unpSize := s.file.GetUnpackSizeOfBlock(s.latestBlock)
		if s.virtPos < block.UnpPos || s.virtPos-block.UnpPos >= unpSize {
			s.latestBlock = -1
		}
	}

	if s.latestBlock < 0 {
		s.latestChunk = -1
		blockIndex := s.findBlock(s.virtPos)
		block := s.file.Blocks[blockIndex]
		unpSize := s.file.GetUnpackSizeOfBlock(blockIndex)

		// Check if we can cache this block
		if block.NeedAllocateBuffer() && unpSize <= ChunkSizeMax {
			// Try to find the block in the cache
			chunkIndex := -1
			for i, chunk := range s.chunks {
				if chunk.BlockIndex == blockIndex {
					chunkIndex = i
					break
				}
			}

			if chunkIndex >= 0 {
				s.latestChunk = chunkIndex
			} else {
				// Need to load the block
				chunk, err := s.loadBlock(blockIndex)
				if err != nil {
					s.errorMode = true
					return 0, err
				}
				s.latestChunk = chunk
			}
		}

		s.latestBlock = blockIndex
	}

	// Read from the current block
	block := s.file.Blocks[s.latestBlock]
	offset := s.virtPos - block.UnpPos

	// Adjust read size to block boundaries
	blockSize := s.file.GetUnpackSizeOfBlock(s.latestBlock)
	if offset+toRead > blockSize {
		toRead = blockSize - offset
	}

	// Perform the actual read
	var bytesRead int
	if block.IsZeroMethod() {
		// Zero block - fill with zeros
		for i := uint64(0); i < toRead; i++ {
			p[i] = 0
		}
		bytesRead = int(toRead)
	} else if s.latestChunk >= 0 {
		// Read from cached chunk
		chunk := s.chunks[s.latestChunk]
		copy(p[:toRead], chunk.Buf[offset:offset+toRead])
		chunk.AccessMark = s.accessMark
		s.accessMark++
		bytesRead = int(toRead)
	} else if block.Type == MethodCopy {
		// Direct read from source
		if _, err := s.stream.Seek(int64(s.startPos+s.file.StartPackPos+block.PackPos+offset), io.SeekStart); err != nil {
			return 0, err
		}
		bytesRead, err = s.stream.Read(p[:toRead])
		if err != nil {
			return bytesRead, err
		}
	} else {
		s.errorMode = true
		return 0, errors.New("unsupported block type for direct read")
	}

	s.virtPos += uint64(bytesRead)
	return bytesRead, nil
}

// Seek implements io.Seeker interface
func (s *InStream) Seek(offset int64, whence int) (int64, error) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	var newPos int64
	switch whence {
	case io.SeekStart:
		newPos = offset
	case io.SeekCurrent:
		newPos = int64(s.virtPos) + offset
	case io.SeekEnd:
		newPos = int64(s.size) + offset
	default:
		return int64(s.virtPos), errors.New("invalid whence")
	}

	if newPos < 0 {
		return int64(s.virtPos), errors.New("negative position")
	}

	s.virtPos = uint64(newPos)
	return newPos, nil
}

// findBlock finds the block containing the given position
func (s *InStream) findBlock(pos uint64) int {
	left := 0
	right := len(s.file.Blocks)

	for {
		mid := (left + right) / 2
		if mid == left {
			return left
		}

		if pos < s.file.Blocks[mid].UnpPos {
			right = mid
		} else {
			left = mid
		}
	}
}

// loadBlock loads a block into the cache
func (s *InStream) loadBlock(blockIndex int) (int, error) {
	block := s.file.Blocks[blockIndex]
	unpSize := s.file.GetUnpackSizeOfBlock(blockIndex)

	// Find or create a chunk
	var chunkIndex int
	if len(s.chunks) < int(NumChunksMax) && s.chunksTotalSize+unpSize <= ChunksTotalSizeMax {
		// Can create a new chunk
		chunk := Chunk{
			BlockIndex: -1,
			AccessMark: 0,
		}
		s.chunks = append(s.chunks, chunk)
		chunkIndex = len(s.chunks) - 1
	} else if len(s.chunks) == 0 {
		// No chunks available and can't create more
		return -1, errors.New("no chunks available")
	} else {
		// Reuse the least recently accessed chunk
		chunkIndex = 0
		for i := 1; i < len(s.chunks); i++ {
			if s.chunks[i].AccessMark < s.chunks[chunkIndex].AccessMark {
				chunkIndex = i
			}
		}

		// Free the old chunk's memory
		oldSize := s.chunks[chunkIndex].BufSize
		s.chunks[chunkIndex].Free()
		s.chunksTotalSize -= oldSize
	}

	// Allocate and fill the chunk
	chunk := &s.chunks[chunkIndex]
	chunk.BlockIndex = -1
	chunk.AccessMark = s.accessMark
	s.accessMark++

	if err := chunk.Alloc(unpSize); err != nil {
		return -1, err
	}
	s.chunksTotalSize += unpSize

	// Read and decompress the block
	if _, err := s.stream.Seek(int64(s.startPos+s.file.StartPackPos+block.PackPos), io.SeekStart); err != nil {
		return -1, err
	}

	reader := &LimitedReader{R: s.stream, N: block.PackSize}
	writer := bytes.NewBuffer(chunk.Buf[:0])
	writer.Grow(int(unpSize))

	// Decompress the block
	if block.Type == MethodCopy {
		if block.PackSize != unpSize {
			return -1, errors.New("copy block size mismatch")
		}

		if _, err := io.CopyN(writer, reader, int64(unpSize)); err != nil {
			return -1, err
		}
	} else {
		decoder, err := s.registry.GetDecoder(&block)
		if err != nil {
			return -1, err
		}

		if err := decoder.Decode(reader, writer, unpSize); err != nil {
			return -1, err
		}
	}

	chunk.BlockIndex = blockIndex
	return chunkIndex, nil
}
