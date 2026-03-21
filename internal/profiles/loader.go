package profiles

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// LoadFile reads and parses a profile YAML from disk.
func LoadFile(path string) (*Profile, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading profile %q: %w", path, err)
	}
	return LoadBytes(data)
}

// LoadBytes parses a profile from raw YAML bytes.
func LoadBytes(data []byte) (*Profile, error) {
	var p Profile
	if err := yaml.Unmarshal(data, &p); err != nil {
		return nil, fmt.Errorf("parsing profile YAML: %w", err)
	}
	if err := p.compile(); err != nil {
		return nil, err
	}
	return &p, nil
}
