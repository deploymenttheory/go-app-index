package fileanalyzer

// InstallerMetadata represents standardized metadata extracted from installer files
type InstallerMetadata struct {
	Name             string   // Application name
	Version          string   // Application version
	Publisher        string   // Publisher/vendor name
	BundleIdentifier string   // App bundle identifiers
	PackageIDs       []string // Package identifiers (varies by platform)
	SHASum           []byte   // SHA256 hash of the file
}

// IsValid returns true if the metadata contains at least a name or version
func (im *InstallerMetadata) IsValid() bool {
	return im != nil && (im.Name != "" || im.Version != "")
}

// ToMap converts the metadata to a map for inclusion in Result.Metadata
func (im *InstallerMetadata) ToMap() map[string]interface{} {
	if im == nil {
		return nil
	}

	result := make(map[string]interface{})

	if im.Name != "" {
		result["name"] = im.Name
	}

	if im.Version != "" {
		result["version"] = im.Version
	}

	if im.Publisher != "" {
		result["publisher"] = im.Publisher
	}

	if len(im.PackageIDs) > 0 {
		result["package_ids"] = im.PackageIDs
	}

	if len(im.SHASum) > 0 {
		result["sha256"] = im.SHASum
	}

	return result
}
