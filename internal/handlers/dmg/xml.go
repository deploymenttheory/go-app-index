package dmg

import (
	"bytes"
	"fmt"

	"howett.net/plist"
)

// PlistDocument represents a parsed property list document
type PlistDocument struct {
	Root map[string]interface{}
}

// Parse parses a property list from raw data
func ParsePlist(data []byte) (*PlistDocument, error) {
	var root map[string]interface{}

	decoder := plist.NewDecoder(bytes.NewReader(data))
	if err := decoder.Decode(&root); err != nil {
		return nil, fmt.Errorf("plist parse error: %w", err)
	}

	return &PlistDocument{Root: root}, nil
}

// GetDict returns a dictionary value for the given key
func GetDict(dict map[string]interface{}, key string) (map[string]interface{}, bool) {
	if value, ok := dict[key]; ok {
		if dictValue, ok := value.(map[string]interface{}); ok {
			return dictValue, true
		}
	}
	return nil, false
}

// GetArray returns an array value for the given key
func GetArray(dict map[string]interface{}, key string) ([]interface{}, bool) {
	if value, ok := dict[key]; ok {
		if arrayValue, ok := value.([]interface{}); ok {
			return arrayValue, true
		}
	}
	return nil, false
}

// GetString returns a string value for the given key
func GetString(dict map[string]interface{}, key string) (string, bool) {
	if value, ok := dict[key]; ok {
		if strValue, ok := value.(string); ok {
			return strValue, true
		}
	}
	return "", false
}

// GetData returns a byte array for the given key
// Note: howett.net/plist automatically decodes base64 data
func GetData(dict map[string]interface{}, key string) ([]byte, bool) {
	if value, ok := dict[key]; ok {
		if dataValue, ok := value.([]byte); ok {
			return dataValue, true
		}
	}
	return nil, false
}
