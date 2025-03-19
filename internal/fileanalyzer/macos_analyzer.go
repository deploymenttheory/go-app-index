// macos_analyzer.go
//
// Refactored MacOSAnalyzer with robust handling of .pkg, .dmg, and .app files.
//
// Portions derived from FleetDM's XAR parser implementation:
// https://github.com/fleetdm/fleet
//
// Copyright 2023 SAS Software
// Licensed under Apache License 2.0 (http://www.apache.org/licenses/LICENSE-2.0)

package fileanalyzer

import (
	"compress/bzip2"
	"compress/zlib"
	"crypto/sha256"
	"encoding/binary"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/deploymenttheory/go-app-index/internal/logger"
	"howett.net/plist"
)

const (
	xarMagic      = 0x78617221
	xarHeaderSize = 28
)

type xarHeader struct {
	Magic            uint32
	HeaderSize       uint16
	Version          uint16
	CompressedSize   int64
	UncompressedSize int64
	HashType         uint32
}

type xmlXar struct {
	XMLName xml.Name `xml:"xar"`
	TOC     xmlTOC
}

type xmlTOC struct {
	XMLName xml.Name   `xml:"toc"`
	Files   []*xmlFile `xml:"file"`
}

type xmlFile struct {
	XMLName xml.Name     `xml:"file"`
	Name    string       `xml:"name"`
	Data    *xmlFileData `xml:"data"`
}

type xmlFileData struct {
	Length   int64 `xml:"length"`
	Offset   int64 `xml:"offset"`
	Encoding struct {
		Style string `xml:"style,attr"`
	} `xml:"encoding"`
}

// distributionXML represents the structure of the distributionXML.xml
type distributionXML struct {
	Title          string                     `xml:"title"`
	Product        distributionProduct        `xml:"product"`
	PkgRefs        []distributionPkgRef       `xml:"pkg-ref"`
	Choices        []distributionChoice       `xml:"choice"`
	ChoicesOutline distributionChoicesOutline `xml:"choices-outline"`
}

// distributionProduct represents the product element
type distributionProduct struct {
	ID      string `xml:"id,attr"`
	Version string `xml:"version,attr"`
}

// distributionPkgRef represents the pkg-ref element
type distributionPkgRef struct {
	ID                string                      `xml:"id,attr"`
	Version           string                      `xml:"version,attr"`
	BundleVersions    []distributionBundleVersion `xml:"bundle-version"`
	MustClose         distributionMustClose       `xml:"must-close"`
	PackageIdentifier string                      `xml:"packageIdentifier,attr"`
	InstallKBytes     string                      `xml:"installKBytes,attr"`
}

// distributionBundleVersion represents the bundle-version element
type distributionBundleVersion struct {
	Bundles []distributionBundle `xml:"bundle"`
}

// distributionBundle represents the bundle element
type distributionBundle struct {
	Path                       string `xml:"path,attr"`
	ID                         string `xml:"id,attr"`
	CFBundleShortVersionString string `xml:"CFBundleShortVersionString,attr"`
}

// distributionMustClose represents the must-close element
type distributionMustClose struct {
	Apps []distributionApp `xml:"app"`
}

// distributionApp represents the app element
type distributionApp struct {
	ID string `xml:"id,attr"`
}

type distributionChoice struct {
	PkgRef distributionPkgRef `xml:"pkg-ref"`
	Title  string             `xml:"title,attr"`
	ID     string             `xml:"id,attr"`
}

type distributionChoicesOutline struct {
	Lines []distributionLine `xml:"line"`
}

type distributionLine struct {
	Choice string `xml:"choice,attr"`
}

type packageInfoXML struct {
	Version         string               `xml:"version,attr"`
	InstallLocation string               `xml:"install-location,attr"`
	Identifier      string               `xml:"identifier,attr"`
	Bundles         []distributionBundle `xml:"bundle"`
}

type MacOSAnalyzer struct{}

func (a *MacOSAnalyzer) CanHandle(filePath string, contentType string) bool {
	ext := strings.ToLower(filepath.Ext(filePath))
	logger.Debugf("Checking if MacOSAnalyzer can handle file: %s (ext: %s, type: %s)", filePath, ext, contentType)
	return ext == ".dmg" || ext == ".pkg" || ext == ".app"
}

func (a *MacOSAnalyzer) Analyze(filePath string) (*Result, error) {
	ext := strings.ToLower(filepath.Ext(filePath))
	logger.Debugf("Analyzing file: %s (ext: %s)", filePath, ext)

	switch ext {
	case ".pkg":
		return analyzePKG(filePath)
	case ".app":
		return analyzeAppBundle(filePath)
	default:
		logger.Warningf("Unknown file type for analysis: %s", filePath)
		return &Result{
			FileType:    "unknown",
			Platform:    "macos",
			Confidence:  0.3,
			IsInstaller: false,
			Metadata:    map[string]interface{}{},
			AnalyzedAt:  timeNow(),
		}, nil
	}
}
func analyzePKG(filePath string) (*Result, error) {
	logger.Infof("Starting PKG analysis: %s", filePath)

	file, err := os.Open(filePath)
	if err != nil {
		logger.Errorf("Failed to open PKG file: %s, error: %v", filePath, err)
		return nil, err
	}
	defer file.Close()

	hash := sha256.New()
	size, _ := io.Copy(hash, file)
	file.Seek(0, io.SeekStart)

	var hdr xarHeader
	if err := binary.Read(file, binary.BigEndian, &hdr); err != nil || hdr.Magic != xarMagic {
		logger.Errorf("Invalid PKG file (bad magic number): %s", filePath)
		return nil, errors.New("invalid pkg file")
	}
	logger.Debugf("XAR header read successfully: %+v", hdr)

	zr, err := zlib.NewReader(io.LimitReader(file, hdr.CompressedSize))
	if err != nil {
		logger.Errorf("Failed to create zlib reader for %s: %v", filePath, err)
		return nil, err
	}
	defer zr.Close()

	var toc xmlXar
	decoder := xml.NewDecoder(zr)
	if err := decoder.Decode(&toc); err != nil {
		logger.Errorf("Failed to parse TOC XML for %s: %v", filePath, err)
		return nil, err
	}
	logger.Debugf("Parsed TOC successfully: %d files found", len(toc.TOC.Files))

	heapOffset := xarHeaderSize + hdr.CompressedSize
	for _, f := range toc.TOC.Files {
		if f.Name == "Distribution" || f.Name == "PackageInfo" {
			logger.Debugf("Found key file: %s", f.Name)
			contents, err := readCompressedFile(file, heapOffset, size, f)
			if err != nil {
				logger.Errorf("Failed to read %s from %s: %v", f.Name, filePath, err)
				return nil, err
			}
			meta, err := parseXMLMetadata(contents)
			if err != nil {
				logger.Errorf("Failed to parse metadata from %s: %v", filePath, err)
				return nil, err
			}
			meta.SHASum = hash.Sum(nil)
			logger.Infof("Extracted metadata for PKG: %+v", meta)
			return &Result{
				FileType:    "pkg",
				Platform:    "macos",
				Confidence:  0.95,
				IsInstaller: true,
				Metadata:    meta.ToMap(),
				AnalyzedAt:  timeNow(),
			}, nil
		}
	}
	logger.Warningf("No key metadata found in PKG: %s", filePath)
	return &Result{
		FileType:    "pkg",
		Platform:    "macos",
		Confidence:  0.7,
		IsInstaller: true,
		Metadata:    map[string]interface{}{"note": "PKG internal metadata not found"},
		AnalyzedAt:  timeNow(),
	}, nil
}

func analyzeAppBundle(appPath string) (*Result, error) {
	logger.Infof("Analyzing .app bundle: %s", appPath)
	infoPlistPath := filepath.Join(appPath, "Contents", "Info.plist")
	plistFile, err := os.Open(infoPlistPath)
	if err != nil {
		logger.Errorf("Failed to open Info.plist for %s: %v", appPath, err)
		return nil, err
	}
	defer plistFile.Close()

	var plistData map[string]interface{}
	decoder := plist.NewDecoder(plistFile)
	if err := decoder.Decode(&plistData); err != nil {
		logger.Errorf("Failed to parse Info.plist for %s: %v", appPath, err)
		return nil, err
	}
	logger.Debugf("Extracted plist data: %+v", plistData)

	meta := &InstallerMetadata{
		Name:             plistData["CFBundleName"].(string),
		Version:          plistData["CFBundleShortVersionString"].(string),
		BundleIdentifier: plistData["CFBundleIdentifier"].(string),
		PackageIDs:       []string{plistData["CFBundleIdentifier"].(string)},
	}
	logger.Infof("Extracted metadata for .app: %+v", meta)

	return &Result{
		FileType:    "app",
		Platform:    "macos",
		Confidence:  0.9,
		IsInstaller: false,
		Metadata:    meta.ToMap(),
		AnalyzedAt:  timeNow(),
	}, nil
}

func readCompressedFile(rat io.ReaderAt, heapOffset int64, sectionLength int64, f *xmlFile) ([]byte, error) {
	var fileReader io.Reader
	heapReader := io.NewSectionReader(rat, heapOffset, sectionLength-heapOffset)
	fileReader = io.NewSectionReader(heapReader, f.Data.Offset, f.Data.Length)

	// the distribution file can be compressed differently than the TOC, the
	// actual compression is specified in the Encoding.Style field.
	if strings.Contains(f.Data.Encoding.Style, "x-gzip") {
		// despite the name, x-gzip fails to decode with the gzip package
		// (invalid header), but it works with zlib.
		zr, err := zlib.NewReader(fileReader)
		if err != nil {
			return nil, fmt.Errorf("create zlib reader: %w", err)
		}
		defer zr.Close()
		fileReader = zr
	} else if strings.Contains(f.Data.Encoding.Style, "x-bzip2") {
		fileReader = bzip2.NewReader(fileReader)
	}
	// TODO: what other compression methods are supported?

	contents, err := io.ReadAll(fileReader)
	if err != nil {
		return nil, fmt.Errorf("reading %s file: %w", f.Name, err)
	}
	return contents, nil
}

func parseXMLMetadata(contents []byte) (*InstallerMetadata, error) {
	var distXML distributionXML
	if err := xml.Unmarshal(contents, &distXML); err == nil && distXML.Product.ID != "" {
		name, identifier, version, packageIDs := getDistributionInfo(&distXML)
		return &InstallerMetadata{Name: name, Version: version, BundleIdentifier: identifier, PackageIDs: packageIDs}, nil
	}

	var pkgInfo packageInfoXML
	if err := xml.Unmarshal(contents, &pkgInfo); err == nil {
		name, identifier, version, packageIDs := getPackageInfo(&pkgInfo)
		return &InstallerMetadata{Name: name, Version: version, BundleIdentifier: identifier, PackageIDs: packageIDs}, nil
	}

	return nil, errors.New("unable to parse installer metadata")
}

// getDistributionInfo gets the name, bundle identifier and version of a PKG distribution file
func getDistributionInfo(d *distributionXML) (name string, identifier string, version string, packageIDs []string) {
	var appVersion string

	// find the package ids that have an installation size
	packageIDSet := make(map[string]struct{}, 1)
	for _, pkg := range d.PkgRefs {
		if pkg.InstallKBytes != "" && pkg.InstallKBytes != "0" {
			var id string
			if pkg.PackageIdentifier != "" {
				id = pkg.PackageIdentifier
			} else if pkg.ID != "" {
				id = pkg.ID
			}
			if id != "" {
				packageIDSet[id] = struct{}{}
			}
		}
	}
	if len(packageIDSet) == 0 {
		// if we didn't find any package IDs with installation size, then grab all of them
		for _, pkg := range d.PkgRefs {
			var id string
			if pkg.PackageIdentifier != "" {
				id = pkg.PackageIdentifier
			} else if pkg.ID != "" {
				id = pkg.ID
			}
			if id != "" {
				packageIDSet[id] = struct{}{}
			}
		}
	}
	for id := range packageIDSet {
		packageIDs = append(packageIDs, id)
	}

out:
	// look in all the bundle versions for one that has a `path` attribute
	// that is not nested, this is generally the case for packages that distribute
	// `.app` files, which are ultimately picked up as an installed app by osquery
	for _, pkg := range d.PkgRefs {
		for _, versions := range pkg.BundleVersions {
			for _, bundle := range versions.Bundles {
				if base, isValid := isValidAppFilePath(bundle.Path); isValid {
					identifier = bundle.ID
					name = base
					appVersion = bundle.CFBundleShortVersionString
					break out
				}
			}
		}
	}

	// if we didn't find anything, look for any <pkg-ref> elements and grab
	// the first `<must-close>`, `packageIdentifier` or `id` attribute we
	// find as the bundle identifier, in that order
	if identifier == "" {
		for _, pkg := range d.PkgRefs {
			if len(pkg.MustClose.Apps) > 0 {
				identifier = pkg.MustClose.Apps[0].ID
				break
			}
		}
	}

	// Try to get the identifier based on the choices list, if we have one. Some .pkgs have multiple
	// sub-pkgs inside, so the choices list helps us be a bit smarter.
	if identifier == "" && len(d.ChoicesOutline.Lines) > 0 {
		choicesByID := make(map[string]distributionChoice, len(d.Choices))
		for _, c := range d.Choices {
			choicesByID[c.ID] = c
		}

		for _, l := range d.ChoicesOutline.Lines {
			c := choicesByID[l.Choice]
			// Note: we can't create a map of pkg-refs by ID like we do for the choices above
			// because different pkg-refs can have the same ID attribute. See distribution-go.xml
			// for an example of this (this case is covered in tests).
			for _, p := range d.PkgRefs {
				if p.ID == c.PkgRef.ID {
					identifier = p.PackageIdentifier
					if identifier == "" {
						identifier = p.ID
					}
					break
				}
			}

			if identifier != "" {
				// we found it, so we can quit looping
				break
			}
		}
	}

	if identifier == "" {
		for _, pkg := range d.PkgRefs {
			if pkg.PackageIdentifier != "" {
				identifier = pkg.PackageIdentifier
				break
			}

			if pkg.ID != "" {
				identifier = pkg.ID
				break
			}
		}
	}

	// if the identifier is still empty, try to use the product id
	if identifier == "" && d.Product.ID != "" {
		identifier = d.Product.ID
	}

	// if package IDs are still empty, use the identifier as the package ID
	if len(packageIDs) == 0 && identifier != "" {
		packageIDs = append(packageIDs, identifier)
	}

	// for the name, try to use the title and fallback to the bundle
	// identifier
	if name == "" && d.Title != "" {
		name = d.Title
	}

	if _, ok := knownBadNames[name]; name == "" || ok {
		name = identifier

		// Try to find a <choice> tag that matches the bundle ID for this app. It might have the app
		// name, so if we find it we can use that.
		for _, c := range d.Choices {
			if c.PkgRef.ID == identifier && c.Title != "" {
				name = c.Title
			}
		}
	}

	// for the version, try to use the top-level product version, if not,
	// fallback to any version definition alongside the name or the first
	// version in a pkg-ref we find.
	if d.Product.Version != "" {
		version = d.Product.Version
	}
	if version == "" && appVersion != "" {
		version = appVersion
	}
	if version == "" {
		for _, pkgRef := range d.PkgRefs {
			if pkgRef.Version != "" {
				version = pkgRef.Version
			}
		}
	}

	return name, identifier, version, packageIDs
}

// getPackageInfo gets the name, bundle identifier and version of a PKG top level PackageInfo file
func getPackageInfo(p *packageInfoXML) (name string, identifier string, version string, packageIDs []string) {
	packageIDSet := make(map[string]struct{}, 1)
	for _, bundle := range p.Bundles {
		installPath := bundle.Path
		if p.InstallLocation != "" {
			installPath = filepath.Join(p.InstallLocation, installPath)
		}
		installPath = strings.TrimPrefix(installPath, "/")
		installPath = strings.TrimPrefix(installPath, "./")
		if base, isValid := isValidAppFilePath(installPath); isValid {
			identifier = preprocess(bundle.ID)
			name = base
			version = preprocess(bundle.CFBundleShortVersionString)
		}
		bundleID := preprocess(bundle.ID)
		if bundleID != "" {
			packageIDSet[bundleID] = struct{}{}
		}
	}

	for id := range packageIDSet {
		packageIDs = append(packageIDs, id)
	}

	// if we didn't find a version, grab the version from pkg-info element
	// Note: this version may be wrong since it is the version of the package and not the app
	if version == "" {
		version = preprocess(p.Version)
	}

	// if we didn't find a bundle identifier, grab the identifier from pkg-info element
	if identifier == "" {
		identifier = preprocess(p.Identifier)
	}

	// if we didn't find a name, grab the name from the identifier
	if name == "" {
		idParts := strings.Split(identifier, ".")
		if len(idParts) > 0 {
			name = idParts[len(idParts)-1]
		}
	}

	// if we didn't find package IDs, use the identifier as the package ID
	if len(packageIDs) == 0 && identifier != "" {
		packageIDs = append(packageIDs, identifier)
	}

	return name, identifier, version, packageIDs
}

// isValidAppFilePath checks if the given input is a file name ending with .app
// or if it's in the "Applications" directory with a .app extension.
func isValidAppFilePath(input string) (string, bool) {
	dir, file := filepath.Split(input)

	if dir == "" && file == input {
		return file, true
	}

	if strings.HasSuffix(file, ".app") {
		if dir == "Applications/" {
			return file, true
		}
	}

	return "", false
}

// Set of package names we know are incorrect. If we see these in the Distribution file we should
// try to get the name some other way.
var knownBadNames = map[string]struct{}{
	"DISTRIBUTION_TITLE": {},
	"MacFULL":            {},
	"SU_TITLE":           {},
}

func preprocess(input string) string {
	return strings.TrimSpace(input)
}
