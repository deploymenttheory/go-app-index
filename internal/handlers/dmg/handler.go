package dmg

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"strings"
)

// Handler represents a DMG archive handler
type Handler struct {
	masterCrcError  bool
	headersError    bool
	dataForkError   bool
	rsrcModeWasUsed bool

	files    []*File
	startPos uint64
	phySize  uint64
	name     string

	dataForkPair ForkPair
	rsrcPair     ForkPair
	xmlPair      ForkPair
	blobPair     ForkPair

	numSectors  uint64
	segmentGUID [16]byte

	dataForkChecksum Checksum
	masterChecksum   Checksum
}

// NewHandler creates a new DMG handler
func NewHandler() *Handler {
	return &Handler{
		files:           make([]*File, 0),
		startPos:        0,
		phySize:         0,
		masterCrcError:  false,
		headersError:    false,
		dataForkError:   false,
		rsrcModeWasUsed: false,
	}
}

// Open opens a DMG file
func (h *Handler) Open(r io.ReadSeeker) error {
	h.Close()

	// Get file size
	fileSize, err := r.Seek(0, io.SeekEnd)
	if err != nil {
		return err
	}

	// Try to find the Koly header
	const headerSize = KolyHeaderSize
	header := make([]byte, headerSize)

	// First try at the end (normal case)
	headerPos := fileSize - int64(headerSize)
	if headerPos < 0 {
		return errors.New("file too small")
	}

	if _, err := r.Seek(headerPos, io.SeekStart); err != nil {
		return err
	}

	if _, err := io.ReadFull(r, header); err != nil {
		return err
	}

	frontKolyMode := false

	// Check if we have a valid Koly header
	if !IsKoly(header) {
		// No Koly at the end, try at the beginning
		if _, err := r.Seek(0, io.SeekStart); err != nil {
			return err
		}

		if _, err := io.ReadFull(r, header); err != nil {
			return err
		}

		if !IsKoly(header) {
			return errors.New("invalid DMG file: no Koly header found")
		}

		headerPos = 0
		frontKolyMode = true
	}

	// Parse Koly header
	h.dataForkPair.Parse(header[0x18:])
	h.rsrcPair.Parse(header[0x28:])
	copy(h.segmentGUID[:], header[0x40:0x40+16])
	h.dataForkChecksum.Parse(header[0x50:])
	h.xmlPair.Parse(header[0xD8:])
	h.blobPair.Parse(header[0x128:])
	h.masterChecksum.Parse(header[0x160:])
	h.numSectors = GetBe64(header, 0x1EC) // not aligned for 8-bytes

	// Check if this is a front Koly mode DMG
	if h.dataForkPair.Offset == headerSize && int64(headerSize)+headerPos < fileSize {
		frontKolyMode = true
	}

	// Determine file boundaries
	limit := uint64(0)
	if frontKolyMode {
		limit = uint64(fileSize)
	} else {
		limit = uint64(headerPos)
	}

	top := uint64(0)
	if !h.dataForkPair.UpdateTop(limit, &top) {
		return errors.New("invalid data fork")
	}
	if !h.xmlPair.UpdateTop(limit, &top) {
		return errors.New("invalid XML fork")
	}
	if !h.rsrcPair.UpdateTop(limit, &top) {
		return errors.New("invalid rsrc fork")
	}

	// Blob pair may contain garbage in old DMG files, so we don't error on it
	useBlob := h.blobPair.UpdateTop(limit, &top)

	if frontKolyMode {
		h.phySize = top
	} else {
		h.phySize = uint64(headerPos) + headerSize
		h.startPos = 0

		if top != uint64(headerPos) {
			// Try to determine if this is a DMG with offset
			xmlPair2 := h.xmlPair
			signature := []byte("<?xml version")
			if xmlPair2.Len > uint64(len(signature)) {
				xmlPair2.Len = uint64(len(signature))
			}

			xmlBuf := make([]byte, xmlPair2.Len)
			if _, err := r.Seek(int64(h.startPos+xmlPair2.Offset), io.SeekStart); err != nil {
				return err
			}

			if _, err := io.ReadFull(r, xmlBuf); err != nil || !bytes.Equal(xmlBuf[:len(signature)], signature) {
				// Absolute offset is not OK, probably an archive with offset
				h.startPos = uint64(headerPos) - top
				h.phySize = top + headerSize
			}
		}
	}

	// Parse blob if available
	if useBlob && h.blobPair.Len != 0 && h.blobPair.Len <= (1<<24) {
		blobBuf := make([]byte, h.blobPair.Len)
		if err := h.readData(r, &h.blobPair, blobBuf); err != nil {
			return err
		}

		if !h.parseBlob(blobBuf) {
			h.headersError = true
		}
	}

	// Parse XML or RSRC to get files
	if h.xmlPair.Len == 0 {
		// Try to use RSRC
		if h.rsrcPair.Len < 0x100 || h.rsrcPair.Len > (1<<24) {
			return errors.New("invalid or missing resource fork")
		}

		h.rsrcModeWasUsed = true
		rsrcBuf := make([]byte, h.rsrcPair.Len)
		if err := h.readData(r, &h.rsrcPair, rsrcBuf); err != nil {
			return err
		}

		// Parse RSRC structure
		const rsrcHeadSize = 0x100
		headSize := GetBe32(rsrcBuf, 0)
		footerOffset := GetBe32(rsrcBuf, 4)
		mainDataSize := GetBe32(rsrcBuf, 8)
		footerSize := GetBe32(rsrcBuf, 12)

		if headSize != rsrcHeadSize ||
			footerOffset >= uint32(h.rsrcPair.Len) ||
			mainDataSize >= uint32(h.rsrcPair.Len) ||
			footerOffset < mainDataSize ||
			footerOffset != headSize+mainDataSize {
			return errors.New("invalid resource fork structure")
		}

		footerEnd := footerOffset + footerSize
		if footerEnd != uint32(h.rsrcPair.Len) {
			// There is a rare case DMG example, where there are 4 additional bytes
			rem := uint32(h.rsrcPair.Len) - footerOffset
			if rem < footerSize ||
				rem-footerSize != 4 ||
				GetBe32(rsrcBuf, int(footerEnd)) != 0 {
				return errors.New("invalid resource fork footer")
			}
		}

		// Check that footer matches header
		if !bytes.Equal(rsrcBuf[:16], rsrcBuf[footerOffset:footerOffset+16]) {
			return errors.New("resource fork header/footer mismatch")
		}

		footer := rsrcBuf[footerOffset:]

		// Parse resource map
		if GetBe16(footer, 0x18) != 0x1c {
			return errors.New("invalid resource map structure")
		}

		namesOffset := uint32(GetBe16(footer, 0x1a))
		if namesOffset > footerSize {
			return errors.New("invalid names offset")
		}

		numItems := int(GetBe16(footer, 0x1c)) + 1
		if numItems*8+0x1e > int(namesOffset) {
			return errors.New("invalid number of items")
		}

		// Process each resource type
		for i := 0; i < numItems; i++ {
			p2 := footer[0x1e+i*8:]
			typeID := GetBe32(p2, 0)

			// We're only interested in "blkx" type resources
			if typeID != 0x626c6b78 { // "blkx"
				continue
			}

			numFiles := int(GetBe16(p2, 4)) + 1
			offs := GetBe16(p2, 6)

			if 0x1c+offs+12*uint16(numFiles) > namesOffset {
				return errors.New("invalid file offset")
			}

			// Process each file in this resource type
			for k := 0; k < numFiles; k++ {
				p3 := footer[0x1c+offs+uint16(k*12):]

				namePos := GetBe16(p3, 2)

				// We don't know how many bits we can use. So we use 24 bits only
				blockOffset := GetBe32(p3, 4)
				blockOffset &= ((1 << 24) - 1)

				if blockOffset+4 >= mainDataSize {
					return errors.New("invalid block offset")
				}

				pBlock := rsrcBuf[headSize+blockOffset:]
				blockSize := GetBe32(pBlock, 0)

				if uint32(mainDataSize)-(blockOffset+4) < blockSize {
					return errors.New("invalid block size")
				}

				// Get resource name if available
				var name string
				if namePos != 0xffff {
					namesBlockSize := footerSize - namesOffset
					if namePos >= namesBlockSize {
						return errors.New("invalid name position")
					}

					namePtr := footer[namesOffset+namePos:]
					nameLen := int(namePtr[0])

					if uint32(namesBlockSize)-namePos <= uint32(nameLen) {
						return errors.New("invalid name length")
					}

					// Extract ASCII name
					for r := 1; r <= nameLen; r++ {
						c := namePtr[r]
						if c < 0x20 || c >= 0x80 {
							break
						}
						name += string(c)
					}
				}

				// Create and parse file
				file := NewFile()
				file.Name = name

				if err := file.Parse(pBlock[4 : 4+blockSize]); err != nil {
					return err
				}

				if !file.IsCorrect {
					h.headersError = true
				}

				h.files = append(h.files, file)
			}
		}
	} else {
		// Use XML plist
		if h.xmlPair.Len > XMLSizeMax {
			return errors.New("XML data too large")
		}

		// Read XML data
		xmlBuf := make([]byte, h.xmlPair.Len)
		if _, err := r.Seek(int64(h.startPos+h.xmlPair.Offset), io.SeekStart); err != nil {
			return err
		}

		if _, err := io.ReadFull(r, xmlBuf); err != nil {
			return err
		}

		// Parse XML
		var xml XML
		if ok, err := xml.Parse(string(xmlBuf)); !ok {
			if err != nil {
				return fmt.Errorf("xml parse error: %w", err)
			}
			return errors.New("xml parse error")
		}

		if xml.Root.Name != "plist" {
			return errors.New("invalid plist")
		}

		dictItem := xml.Root.FindSubTag("dict")
		if dictItem == nil {
			return errors.New("missing root dict")
		}

		rfDictItem := FindKeyPair(*dictItem, "resource-fork", "dict")
		if rfDictItem == nil {
			return errors.New("missing resource-fork dict")
		}

		arrItem := FindKeyPair(*rfDictItem, "blkx", "array")
		if arrItem == nil {
			return errors.New("missing blkx array")
		}

		// Process each item in the blkx array
		for _, item := range arrItem.SubItems {
			if !item.IsTagged("dict") {
				continue
			}

			// Get the data from the item
			dataString := GetStringFromKeyPair(item, "Data", "data")
			if dataString == nil {
				return errors.New("missing data in blkx item")
			}

			// Decode base64 data
			data, err := Base64ToBin(*dataString)
			if err != nil {
				return fmt.Errorf("base64 decode error: %w", err)
			}

			// Create and parse file
			file := NewFile()

			// Get file name
			name := GetStringFromKeyPair(item, "Name", "string")
			if name == nil || *name == "" {
				name = GetStringFromKeyPair(item, "CFName", "string")
			}

			if name != nil {
				file.Name = *name
			}

			if err := file.Parse(data); err != nil {
				return err
			}

			if !file.IsCorrect {
				h.headersError = true
			}

			h.files = append(h.files, file)
		}
	}

	// Verify master checksum
	if h.masterChecksum.IsCrc32() {
		crc := CrcInitVal
		for _, file := range h.files {
			cs := file.Checksum
			if (cs.NumBits & 0x7) != 0 {
				break
			}

			len := cs.NumBits >> 3
			if len > ChecksumSizeMax {
				break
			}

			crc = CrcUpdate(crc, cs.Data[:len])
		}

		h.masterCrcError = (CrcGetDigest(crc) != h.masterChecksum.GetCrc32())
	}

	// Verify sector counts
	{
		sec := uint64(0)
		for _, file := range h.files {
			if file.StartUnpackSector != sec {
				h.headersError = true
			}
			if file.NumUnpackSectors >= SectorNumberLimit {
				h.headersError = true
			}
			sec += file.NumUnpackSectors
			if sec >= SectorNumberLimit {
				h.headersError = true
			}
		}
		if sec != h.numSectors {
			h.headersError = true
		}
	}

	// Verify data fork checksum
	if h.dataForkChecksum.IsCrc32() {
		endPos, ok := h.dataForkPair.GetEndPos()
		if !ok || h.dataForkPair.Offset >= (uint64(1)<<63) {
			h.headersError = true
		} else {
			seekPos := h.startPos + h.dataForkPair.Offset

			// Check for bounds
			if _, err := r.Seek(0, io.SeekEnd); err != nil {
				return err
			}

			fileSize, err := r.Seek(0, io.SeekCurrent)
			if err != nil {
				return err
			}

			if seekPos > uint64(fileSize) || endPos > uint64(fileSize)-h.startPos {
				h.headersError = true
			} else {
				// Calculate checksum
				const bufSize = 1 << 15
				buf := make([]byte, bufSize)

				if _, err := r.Seek(int64(seekPos), io.SeekStart); err != nil {
					return err
				}

				crc := CrcInitVal
				pos := uint64(0)

				for {
					rem := h.dataForkPair.Len - pos
					cur := uint64(bufSize)
					if cur > rem {
						cur = rem
					}

					if cur == 0 {
						break
					}

					if _, err := io.ReadFull(r, buf[:cur]); err != nil {
						return err
					}

					crc = CrcUpdate(crc, buf[:cur])
					pos += cur
				}

				if h.dataForkChecksum.GetCrc32() != CrcGetDigest(crc) {
					h.dataForkError = true
				}
			}
		}
	}

	return nil
}

// parseBlob parses the blob section of a DMG file
func (h *Handler) parseBlob(data []byte) bool {
	const kHeaderSize = 3 * 4
	if len(data) < kHeaderSize {
		return false
	}

	// Check for CSMAGIC_EMBEDDED_SIGNATURE
	if GetBe32a(data, 0) != 0xfade0cc0 {
		return true
	}

	size := GetBe32a(data, 4)
	if uint32(size) != uint32(len(data)) {
		return false
	}

	num := GetBe32a(data, 8)
	if num > (uint32(len(data))-kHeaderSize)/8 {
		return false
	}

	limit := num*8 + kHeaderSize
	for i := uint32(kHeaderSize); i < limit; i += 8 {
		offset := GetBe32a(data, int(i+4))
		if offset < limit || offset > uint32(len(data))-8 {
			return false
		}

		// offset is not aligned for 4 here
		p2 := data[offset:]
		magic := GetBe32(p2, 0)
		length := GetBe32(p2, 4)

		if uint32(len(data))-offset < length || length < 8 {
			return false
		}

		// CSMAGIC_CODEDIRECTORY
		if magic == 0xfade0c02 {
			if length < 11*4 {
				return false
			}

			idOffset := GetBe32(p2, 5*4)
			if idOffset >= length {
				return false
			}

			len2 := length - idOffset
			const kNameLenMax = 1 << 8
			if len2 > kNameLenMax {
				len2 = kNameLenMax
			}

			h.name = string(p2[idOffset : idOffset+len2])
		}
	}

	return true
}

// readData reads data from a fork pair
func (h *Handler) readData(r io.ReadSeeker, pair *ForkPair, buf []byte) error {
	if _, err := r.Seek(int64(h.startPos+pair.Offset), io.SeekStart); err != nil {
		return err
	}

	if _, err := io.ReadFull(r, buf); err != nil {
		return err
	}

	return nil
}

// GetNumberOfFiles returns the number of files in the archive
func (h *Handler) GetNumberOfFiles() int {
	return len(h.files)
}

// GetFile returns the file at the given index
func (h *Handler) GetFile(index int) (*File, error) {
	if index < 0 || index >= len(h.files) {
		return nil, errors.New("index out of range")
	}

	return h.files[index], nil
}

// GetStream returns a reader for the file at the given index
func (h *Handler) GetStream(r io.ReadSeeker, index int) (io.ReadSeeker, error) {
	if index < 0 || index >= len(h.files) {
		return nil, errors.New("index out of range")
	}

	file := h.files[index]
	if !file.IsCorrect {
		return nil, errors.New("file is not correct")
	}

	// Check all blocks
	for i, block := range file.Blocks {
		if !block.NeedAllocateBuffer() {
			continue
		}

		unpSize := file.GetUnpackSizeOfBlock(i)
		if unpSize > ChunkSizeMax {
			return nil, errors.New("block too large")
		}

		switch block.Type {
		case MethodCopy:
			// Copy blocks are handled directly
		case MethodADC, MethodZLIB, MethodBZIP2, MethodLZFSE, MethodXZ:
			// These types are supported
		default:
			return nil, errors.New("unsupported block type")
		}
	}

	return NewInStream(r, file, h.startPos+h.dataForkPair.Offset), nil
}

// ExtractFile extracts a file to the given writer
func (h *Handler) ExtractFile(r io.ReadSeeker, index int, w io.Writer) error {
	stream, err := h.GetStream(r, index)
	if err != nil {
		return err
	}

	file := h.files[index]
	_, err = io.CopyN(w, stream, int64(file.Size))
	return err
}

// GetComment returns a comment about the archive
func (h *Handler) GetComment() string {
	var comment strings.Builder

	if h.name != "" {
		AddToCommentProp(&comment, "Name", h.name)
	}

	AddToCommentUInt64(&comment, h.numSectors<<9, "unpack-size")

	// Add segment GUID
	guidStr := ConvertDataToHexLower(h.segmentGUID[:])
	AddToCommentProp(&comment, "ID", guidStr)

	h.masterChecksum.AddToComment(&comment, "master-checksum")
	h.dataForkChecksum.AddToComment(&comment, "pack-checksum")

	h.dataForkPair.Print(&comment, "pack")
	h.rsrcPair.Print(&comment, "rsrc")
	h.xmlPair.Print(&comment, "xml")
	h.blobPair.Print(&comment, "blob")

	if h.rsrcModeWasUsed {
		comment.WriteString("RSRC_MODE\n")
	}

	return comment.String()
}

// Close closes the handler
func (h *Handler) Close() {
	h.masterCrcError = false
	h.headersError = false
	h.dataForkError = false
	h.rsrcModeWasUsed = false
	h.phySize = 0
	h.startPos = 0
	h.name = ""
	h.files = h.files[:0]
}
