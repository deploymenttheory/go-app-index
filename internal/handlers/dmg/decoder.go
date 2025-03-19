package dmg

import (
	"compress/bzip2"
	"compress/zlib"
	"errors"
	"io"

	"github.com/ulikunitz/xz"
)

// Decoder interface for all compression methods
type Decoder interface {
	Decode(r io.Reader, w io.Writer, unpSize uint64) error
}

// Bzip2Decoder implements bzip2 decompression
type Bzip2Decoder struct{}

// Decode decompresses bzip2 data
func (d *Bzip2Decoder) Decode(r io.Reader, w io.Writer, unpSize uint64) error {
	br := bzip2.NewReader(r)

	written, err := io.CopyN(w, br, int64(unpSize))
	if err != nil && err != io.EOF {
		return err
	}
	if written != int64(unpSize) {
		return errors.New("bzip2: unexpected size")
	}

	return nil
}

// XzDecoder implements xz decompression
type XzDecoder struct {
	Stat struct {
		InSize uint64
	}
}

// Decode decompresses xz data
func (d *XzDecoder) Decode(r io.Reader, w io.Writer, unpSize uint64) error {
	// Keep track of input size
	countingReader := &countReader{r: r}

	// Create xz reader
	xr, err := xz.NewReader(countingReader)
	if err != nil {
		return err
	}

	written, err := io.CopyN(w, xr, int64(unpSize))
	if err != nil && err != io.EOF {
		return err
	}
	if written != int64(unpSize) {
		return errors.New("xz: unexpected size")
	}

	d.Stat.InSize = countingReader.n
	return nil
}

// countReader wraps a reader and counts bytes read
type countReader struct {
	r io.Reader
	n uint64
}

func (r *countReader) Read(p []byte) (int, error) {
	n, err := r.r.Read(p)
	r.n += uint64(n)
	return n, err
}

// LzfseDecoder implements LZFSE decompression
// Note: This is a placeholder. Apple's LZFSE would need a native Go implementation
type LzfseDecoder struct{}

// Decode decompresses LZFSE data
func (d *LzfseDecoder) Decode(r io.Reader, w io.Writer, unpSize uint64) error {
	// In a real implementation, we would need to implement LZFSE decompression
	// For now, we return an error
	return errors.New("lzfse decompression not implemented")
}

// CopyDecoder implements simple copying (no compression)
type CopyDecoder struct{}

// Decode simply copies data
func (d *CopyDecoder) Decode(r io.Reader, w io.Writer, unpSize uint64) error {
	written, err := io.CopyN(w, r, int64(unpSize))
	if err != nil && err != io.EOF {
		return err
	}
	if written != int64(unpSize) {
		return errors.New("copy: unexpected size")
	}

	return nil
}

// AdcDecoder implements Apple Data Compression decompression
type AdcDecoder struct {
	outWindow *lzOutWindow
	inStream  *inBuffer
}

// Decode decompresses ADC data
func (d *AdcDecoder) Decode(r io.Reader, w io.Writer, unpSize uint64) error {
	// Initialize decompression components if needed
	if d.outWindow == nil {
		d.outWindow = newLzOutWindow(1 << 18) // at least (1 << 16) is required here
	}
	if d.inStream == nil {
		d.inStream = newInBuffer(1 << 18)
	}

	// Set up streams
	d.outWindow.setStream(w)
	d.outWindow.init(false)
	d.inStream.setStream(r)
	d.inStream.init()

	pos := uint64(0)

	// Main decompression loop
	for pos < unpSize {
		// Read control byte
		b, err := d.inStream.readByte()
		if err != nil {
			return err
		}

		rem := unpSize - pos

		if b&0x80 != 0 {
			// Literal sequence
			num := uint(b) - 0x80 + 1
			if uint64(num) > rem {
				return errors.New("adc: corrupt data")
			}

			pos += uint64(num)
			for i := uint(0); i < num; i++ {
				b, err := d.inStream.readByte()
				if err != nil {
					return err
				}

				if err := d.outWindow.putByte(b); err != nil {
					return err
				}
			}

		} else {
			// Match sequence
			b1, err := d.inStream.readByte()
			if err != nil {
				return err
			}

			var length, distance uint32

			if b&0x40 != 0 {
				// Long match
				length = uint32(b) - 0x40 + 4
				b2, err := d.inStream.readByte()
				if err != nil {
					return err
				}
				distance = (uint32(b1) << 8) + uint32(b2)
			} else {
				// Short match
				length = (uint32(b) >> 2) + 3
				distance = ((uint32(b) & 3) << 8) + uint32(b1)
			}

			if uint64(length) > rem {
				return errors.New("adc: corrupt data")
			}

			if err := d.outWindow.copyBlock(distance, length); err != nil {
				return err
			}
			pos += uint64(length)
		}
	}

	return d.outWindow.flush()
}

// lzOutWindow implements a sliding window for LZ-based decompression
type lzOutWindow struct {
	buf       []byte
	pos       uint32
	size      uint32
	isFull    bool
	outStream io.Writer
}

// newLzOutWindow creates a new LZ output window
func newLzOutWindow(size uint32) *lzOutWindow {
	return &lzOutWindow{
		buf:  make([]byte, size),
		size: size,
	}
}

// init initializes the window
func (w *lzOutWindow) init(solid bool) {
	if !solid {
		w.pos = 0
		w.isFull = false
	}
}

// setStream sets the output stream
func (w *lzOutWindow) setStream(outStream io.Writer) {
	w.outStream = outStream
}

// flush flushes any remaining data
func (w *lzOutWindow) flush() error {
	// No buffering in this implementation
	return nil
}

// putByte adds a byte to the window and writes it to the output
func (w *lzOutWindow) putByte(b byte) error {
	w.buf[w.pos] = b
	w.pos = (w.pos + 1) % w.size

	if w.pos == 0 {
		w.isFull = true
	}

	_, err := w.outStream.Write([]byte{b})
	return err
}

// copyBlock copies a block from the window
func (w *lzOutWindow) copyBlock(distance, length uint32) error {
	if distance >= w.size {
		return errors.New("lz: invalid distance")
	}

	// Calculate start position
	copyPos := w.pos
	if distance >= copyPos {
		if !w.isFull {
			return errors.New("lz: invalid position")
		}
		copyPos = w.size - (distance - copyPos)
	} else {
		copyPos = copyPos - distance
	}

	// Handle copying that may wrap around the buffer
	for i := uint32(0); i < length; i++ {
		b := w.buf[copyPos]
		copyPos = (copyPos + 1) % w.size

		if err := w.putByte(b); err != nil {
			return err
		}
	}

	return nil
}

// inBuffer is a buffered input stream
type inBuffer struct {
	buf       []byte
	pos       uint32
	size      uint32
	processed uint64
	stream    io.Reader
}

// newInBuffer creates a new input buffer
func newInBuffer(bufSize uint32) *inBuffer {
	return &inBuffer{
		buf: make([]byte, bufSize),
	}
}

// init initializes the buffer
func (b *inBuffer) init() {
	b.pos = 0
	b.size = 0
	b.processed = 0
}

// setStream sets the input stream
func (b *inBuffer) setStream(stream io.Reader) {
	b.stream = stream
}

// readBlock reads a block of data into the buffer
func (b *inBuffer) readBlock() error {
	b.pos = 0
	n, err := b.stream.Read(b.buf)
	b.size = uint32(n)
	return err
}

// readByte reads a single byte
func (b *inBuffer) readByte() (byte, error) {
	if b.pos >= b.size {
		err := b.readBlock()
		if err != nil && (err != io.EOF || b.size == 0) {
			return 0, err
		}
	}

	result := b.buf[b.pos]
	b.pos++
	b.processed++
	return result, nil
}

// DecoderRegistry holds all available decoders
type DecoderRegistry struct {
	zlib  *ZlibDecoder
	bzip2 *Bzip2Decoder
	lzfse *LzfseDecoder
	xz    *XzDecoder
	adc   *AdcDecoder
	copy  *CopyDecoder
}

// NewDecoderRegistry creates a new DecoderRegistry
func NewDecoderRegistry() *DecoderRegistry {
	return &DecoderRegistry{
		zlib:  &ZlibDecoder{},
		bzip2: &Bzip2Decoder{},
		lzfse: &LzfseDecoder{},
		xz:    &XzDecoder{},
		adc:   &AdcDecoder{},
		copy:  &CopyDecoder{},
	}
}

// GetDecoder returns the appropriate decoder for a block
func (r *DecoderRegistry) GetDecoder(block *Block) (Decoder, error) {
	switch block.Type {
	case MethodADC:
		return r.adc, nil
	case MethodZLIB:
		return r.zlib, nil
	case MethodBZIP2:
		return r.bzip2, nil
	case MethodLZFSE:
		return r.lzfse, nil
	case MethodXZ:
		return r.xz, nil
	case MethodCopy:
		return r.copy, nil
	default:
		return nil, errors.New("unsupported method")
	}
}

// ZlibDecoder implements zlib decompression
type ZlibDecoder struct{}

// Decode decompresses zlib data
func (d *ZlibDecoder) Decode(r io.Reader, w io.Writer, unpSize uint64) error {
	zr, err := zlib.NewReader(r)
	if err != nil {
		return err
	}
	defer zr.Close()

	written, err := io.CopyN(w, zr, int64(unpSize))
	if err != nil && err != io.EOF {
		return err
	}
	if written != int64(unpSize) {
		return errors.New("zlib: unexpected size")
	}

	return nil
}
