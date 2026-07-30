package contracts

import (
	"fmt"
	"sort"
)

// ProviderContractsFile freezes compact data and lifecycle expectations for later providers.
type ProviderContractsFile struct {
	SchemaVersion int                `json:"schema_version"`
	Contracts     []ProviderContract `json:"contracts"`
}

// ProviderContract is contract-only and creates no provider implementation or authority.
type ProviderContract struct {
	Kind                string   `json:"kind"`
	Version             int      `json:"version"`
	Capabilities        []string `json:"capabilities"`
	Lifecycle           []string `json:"lifecycle"`
	Ownership           string   `json:"ownership"`
	FailureTruth        string   `json:"failure_truth"`
	ImplementationState string   `json:"implementation_state"`
}

var requiredProviderKinds = []string{
	"browser_pack", "device", "guest_image", "network", "protocol_edge", "storage", "vmm", "workspace",
}

// ParseProviderContracts rejects unknown fields and incomplete or speculative provider sets.
func ParseProviderContracts(data []byte) (ProviderContractsFile, error) {
	var file ProviderContractsFile
	if err := DecodeStrict(data, &file); err != nil {
		return ProviderContractsFile{}, err
	}
	if file.SchemaVersion != 1 {
		return ProviderContractsFile{}, fmt.Errorf("unsupported provider contract version %d", file.SchemaVersion)
	}
	seen := make(map[string]bool, len(file.Contracts))
	for index, contract := range file.Contracts {
		if contract.Kind == "" || seen[contract.Kind] {
			return ProviderContractsFile{}, fmt.Errorf("provider contract %d: invalid or duplicate kind %q", index, contract.Kind)
		}
		seen[contract.Kind] = true
		if contract.Version != 1 || len(contract.Capabilities) == 0 || len(contract.Lifecycle) == 0 {
			return ProviderContractsFile{}, fmt.Errorf("provider contract %q: version, capabilities, and lifecycle are required", contract.Kind)
		}
		if err := validateUniqueNames("provider capability", contract.Capabilities); err != nil {
			return ProviderContractsFile{}, err
		}
		if err := validateUniqueNames("provider lifecycle phase", contract.Lifecycle); err != nil {
			return ProviderContractsFile{}, err
		}
		if contract.Ownership != "owned_resources_only" || contract.FailureTruth != "explicit" || contract.ImplementationState != "contract_only" {
			return ProviderContractsFile{}, fmt.Errorf("provider contract %q weakens ownership, failure truth, or Mission 1 boundary", contract.Kind)
		}
	}
	for _, kind := range requiredProviderKinds {
		if !seen[kind] {
			return ProviderContractsFile{}, fmt.Errorf("missing provider contract %q", kind)
		}
	}
	if len(seen) != len(requiredProviderKinds) {
		return ProviderContractsFile{}, fmt.Errorf("unexpected provider contract count %d", len(seen))
	}
	sort.Slice(file.Contracts, func(i, j int) bool { return file.Contracts[i].Kind < file.Contracts[j].Kind })
	return file, nil
}
