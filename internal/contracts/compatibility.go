package contracts

import (
	"fmt"
	"sort"
)

// CompatibilityFile is the strict human-authored foundation compatibility contract.
type CompatibilityFile struct {
	SchemaVersion int                    `json:"schema_version"`
	Contracts     []CompatibilityVersion `json:"contracts"`
}

// CompatibilityVersion binds a named contract to an exact initial version.
type CompatibilityVersion struct {
	Name    string `json:"name"`
	Version int    `json:"version"`
}

var requiredCompatibilityNames = []string{
	"dependency_lock",
	"error_envelope",
	"idempotency",
	"input_output_schema",
	"machine_manifest",
	"operation_catalog",
	"operation_registry_source",
	"provider_contract",
	"release_manifest",
	"result_envelope",
}

// ParseCompatibility validates the complete Mission 1 compatibility set.
func ParseCompatibility(data []byte) (CompatibilityFile, error) {
	var file CompatibilityFile
	if err := DecodeStrict(data, &file); err != nil {
		return CompatibilityFile{}, err
	}
	if file.SchemaVersion != 1 {
		return CompatibilityFile{}, fmt.Errorf("unsupported compatibility schema version %d", file.SchemaVersion)
	}
	seen := make(map[string]bool, len(file.Contracts))
	for index, contract := range file.Contracts {
		if contract.Name == "" {
			return CompatibilityFile{}, fmt.Errorf("compatibility contract %d: missing name", index)
		}
		if contract.Version != 1 {
			return CompatibilityFile{}, fmt.Errorf("compatibility contract %q: unsupported version %d", contract.Name, contract.Version)
		}
		if seen[contract.Name] {
			return CompatibilityFile{}, fmt.Errorf("duplicate compatibility contract %q", contract.Name)
		}
		seen[contract.Name] = true
	}
	for _, name := range requiredCompatibilityNames {
		if !seen[name] {
			return CompatibilityFile{}, fmt.Errorf("missing compatibility contract %q", name)
		}
	}
	if len(seen) != len(requiredCompatibilityNames) {
		return CompatibilityFile{}, fmt.Errorf("unexpected compatibility contract count %d", len(seen))
	}
	sort.Slice(file.Contracts, func(i, j int) bool { return file.Contracts[i].Name < file.Contracts[j].Name })
	return file, nil
}

// Map returns a copy suitable for public version and diagnostic output.
func (file CompatibilityFile) Map() map[string]int {
	result := make(map[string]int, len(file.Contracts))
	for _, contract := range file.Contracts {
		result[contract.Name] = contract.Version
	}
	return result
}
