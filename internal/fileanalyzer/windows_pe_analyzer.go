package fileanalyzer

import (
	"crypto/sha256"
	"crypto/x509"
	"debug/pe"
	"encoding/hex"
	"encoding/pem"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/deploymenttheory/go-app-index/internal/logger"
)

// PEAnalyzer analyzes Windows PE (Portable Executable) files
type PEAnalyzer struct{}

// CanHandle checks if the file is a potential Windows PE file
func (a *PEAnalyzer) CanHandle(filePath string, contentType string) bool {
	// Ensure the file has a valid PE extension
	ext := strings.ToLower(filepath.Ext(filePath))
	if ext != ".exe" && ext != ".msi" && ext != ".dll" && ext != ".sys" {
		return false
	}

	// Open the PE file to inspect its contents
	file, err := pe.Open(filePath)
	if err != nil {
		logger.Warningf("Failed to open file %s as a PE: %v", filePath, err)
		return false
	}
	defer file.Close()

	// Check if it contains embedded MSI or DLL files
	for _, section := range file.Sections {
		sectionData, err := section.Data()
		if err != nil {
			continue
		}

		if strings.Contains(string(sectionData), "MSI") {
			logger.Infof("File %s contains an embedded MSI", filePath)
			return true
		}
		if strings.Contains(string(sectionData), "DLL") {
			logger.Infof("File %s contains an embedded DLL", filePath)
			return true
		}
	}

	return true
}

// Analyze extracts metadata from a PE file
func (a *PEAnalyzer) Analyze(filePath string) (*Result, error) {
	file, err := pe.Open(filePath)
	if err != nil {
		logger.Errorf("Failed to open PE file: %v", err)
		return nil, err
	}
	defer file.Close()

	metadata := make(map[string]interface{})

	// Extract basic PE metadata
	metadata["bitness"] = getBitness(file)
	metadata["subsystem"] = getSubsystem(file)
	metadata["imported_libraries"], _ = file.ImportedLibraries()
	metadata["imported_symbols"], _ = file.ImportedSymbols()

	// Extract version & publisher info
	versionInfo, err := extractVersionInfo(filePath)
	if err == nil && versionInfo != nil {
		for k, v := range versionInfo {
			metadata[k] = v
		}
	}

	// Detect installer type
	installerType := detectInstallerType(filePath)
	if installerType != "" {
		metadata["installer_type"] = installerType
	}

	// Check digital signature
	isSigned, signatureInfo := checkSignature(filePath)
	metadata["is_signed"] = isSigned
	if isSigned && signatureInfo != nil {
		for k, v := range signatureInfo {
			metadata["signature_"+k] = v
		}
	}

	// Calculate SHA-256 hash
	sha256Hash, err := calculateSHA256(filePath)
	if err == nil {
		metadata["sha256"] = sha256Hash
	}

	fileType := "exe"
	if strings.HasSuffix(strings.ToLower(filePath), ".msi") {
		fileType = "msi"
	}

	logger.Infof("Analyzed PE file: %s, type=%s, signed=%v", filePath, fileType, isSigned)

	return &Result{
		FileType:    fileType,
		Platform:    "windows",
		Confidence:  0.9,
		IsInstaller: installerType != "",
		Metadata:    metadata,
		AnalyzedAt:  timeNow(),
	}, nil
}

func getBitness(file *pe.File) string {
	switch file.Machine {
	case pe.IMAGE_FILE_MACHINE_AMD64, pe.IMAGE_FILE_MACHINE_IA64:
		return "64-bit"
	default:
		return "32-bit"
	}
}

func getSubsystem(file *pe.File) string {
	if hdr, ok := file.OptionalHeader.(*pe.OptionalHeader64); ok {
		switch hdr.Subsystem {
		case pe.IMAGE_SUBSYSTEM_WINDOWS_GUI:
			return "gui"
		case pe.IMAGE_SUBSYSTEM_WINDOWS_CUI:
			return "console"
		}
	} else if hdr, ok := file.OptionalHeader.(*pe.OptionalHeader32); ok {
		switch hdr.Subsystem {
		case pe.IMAGE_SUBSYSTEM_WINDOWS_GUI:
			return "gui"
		case pe.IMAGE_SUBSYSTEM_WINDOWS_CUI:
			return "console"
		}
	}
	return "unknown"
}

func extractVersionInfo(filePath string) (map[string]string, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, err
	}

	info := make(map[string]string)
	patterns := map[string]string{
		"version":      `(?i)ProductVersion[\s\x00]+([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)`,
		"company":      `(?i)CompanyName[\s\x00]+([^\x00]{3,50})`,
		"product_name": `(?i)ProductName[\s\x00]+([^\x00]{3,50})`,
	}

	for key, pattern := range patterns {
		matches := regexp.MustCompile(pattern).FindStringSubmatch(string(data))
		if len(matches) > 1 {
			info[key] = strings.TrimSpace(matches[1])
		}
	}

	return info, nil
}

func detectInstallerType(filePath string) string {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return ""
	}

	patterns := map[string]string{
		"installshield": `(?i)InstallShield`,
		"nsis":          `(?i)NSIS`,
		"inno_setup":    `(?i)Inno Setup`,
		"msi":           `(?i)Windows Installer`,
	}

	for installer, pattern := range patterns {
		if regexp.MustCompile(pattern).MatchString(string(data)) {
			return installer
		}
	}

	return ""
}

func checkSignature(filePath string) (bool, map[string]string) {
	file, err := os.Open(filePath)
	if err != nil {
		logger.Errorf("Failed to open file for signature check: %v", err)
		return false, nil
	}
	defer file.Close()

	info := make(map[string]string)
	buf := make([]byte, 4096)
	if _, err := file.Read(buf); err != nil {
		logger.Errorf("Failed to read file for signature check: %v", err)
		return false, nil
	}

	block, _ := pem.Decode(buf)
	if block == nil {
		logger.Warningf("No digital signature found in %s", filePath)
		return false, nil
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		logger.Errorf("Failed to parse certificate: %v", err)
		return false, nil
	}

	info["issuer"] = cert.Issuer.String()
	info["subject"] = cert.Subject.String()
	info["valid_from"] = cert.NotBefore.String()
	info["valid_to"] = cert.NotAfter.String()
	info["thumbprint"] = hex.EncodeToString(cert.RawSubjectPublicKeyInfo)

	return true, info
}

func calculateSHA256(filePath string) (string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return "", err
	}
	defer file.Close()

	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return "", err
	}

	return hex.EncodeToString(hash.Sum(nil)), nil
}
