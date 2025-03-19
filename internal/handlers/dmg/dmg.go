package dmg

import (
	"io"
	"os"
	"path/filepath"
)

// OpenFile opens a DMG file at the given path
func OpenFile(path string) (*Handler, *os.File, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, nil, err
	}

	handler := NewHandler()
	if err := handler.Open(file); err != nil {
		file.Close()
		return nil, nil, err
	}

	return handler, file, nil
}

// ExtractFile extracts a file from the DMG to the given path
func ExtractFile(handler *Handler, reader io.ReadSeeker, index int, outputPath string) error {
	// Create output directory if it doesn't exist
	dir := filepath.Dir(outputPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}

	// Open output file
	outFile, err := os.Create(outputPath)
	if err != nil {
		return err
	}
	defer outFile.Close()

	// Extract the file
	return handler.ExtractFile(reader, index, outFile)
}

// ExtractAll extracts all files to the given directory
func ExtractAll(handler *Handler, reader io.ReadSeeker, outputDir string) error {
	// Create output directory
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		return err
	}

	// Extract each file
	for i := 0; i < handler.GetNumberOfFiles(); i++ {
		file, err := handler.GetFile(i)
		if err != nil {
			return err
		}

		// Generate output path
		name := file.Name
		if name == "" {
			name = "file_" + string(i)
		}

		// Try to find extension based on Apple filesystem type
		ext := FindAppleFSExt(name)
		if ext != "" {
			name = "image." + ext
		}

		outPath := filepath.Join(outputDir, name)

		// Extract the file
		if err := ExtractFile(handler, reader, i, outPath); err != nil {
			return err
		}
	}

	return nil
}

// Information about a DMG file
type Info struct {
	Name         string
	NumFiles     int
	UnpackedSize uint64
	PackedSize   uint64
	MasterCrcOK  bool
	HeadersOK    bool
	DataForkOK   bool
	Comment      string
}

// GetInfo returns information about a DMG file
func GetInfo(handler *Handler) *Info {
	info := &Info{
		Name:         handler.name,
		NumFiles:     handler.GetNumberOfFiles(),
		UnpackedSize: handler.numSectors << 9,
		PackedSize:   handler.dataForkPair.Len,
		MasterCrcOK:  !handler.masterCrcError,
		HeadersOK:    !handler.headersError,
		DataForkOK:   !handler.dataForkError,
		Comment:      handler.GetComment(),
	}

	return info
}
