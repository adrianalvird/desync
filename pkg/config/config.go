// pkg/config/config.go

package config

import (
	"encoding/json"
	"os"
)

// TargetEntry represents one URL from the input file.
type TargetEntry struct {
	Status string `json:"status"`
	URL    string `json:"url"`
}

// LoadTargets reads the target JSON file.
func LoadTargets(path string) ([]TargetEntry, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var entries []TargetEntry
	if err := json.Unmarshal(data, &entries); err != nil {
		return nil, err
	}
	return entries, nil
}