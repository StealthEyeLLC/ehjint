package contracts

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
)

var (
	sha256Pattern       = regexp.MustCompile(`^[0-9a-f]{64}$`)
	gitObjectPattern    = regexp.MustCompile(`^[0-9a-f]{40}$`)
	machineNamePattern  = regexp.MustCompile(`^[a-z][a-z0-9-]{0,62}$`)
	objectNamePattern   = regexp.MustCompile(`^[a-z][a-z0-9_-]{0,63}$`)
	productVersionRegex = regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?$`)
)

// ComponentBinding binds one exact provider component into a manifest.
type ComponentBinding struct {
	Provider string `json:"provider"`
	Version  string `json:"version"`
	Digest   string `json:"digest"`
}

// CPUConfiguration is the strict portable CPU declaration.
type CPUConfiguration struct {
	VCPUs int    `json:"vcpus"`
	Mode  string `json:"mode"`
}

// MemoryConfiguration declares guest memory without hidden defaults.
type MemoryConfiguration struct {
	Bytes     uint64 `json:"bytes"`
	HugePages bool   `json:"huge_pages"`
}

// DiskBinding requires an explicit format and immutable/base-overlay identities.
type DiskBinding struct {
	ID         string `json:"id"`
	Role       string `json:"role"`
	Format     string `json:"format"`
	BaseDigest string `json:"base_digest"`
	OverlayID  string `json:"overlay_id"`
}

// NetworkInterfaceBinding is a declared guest interface.
type NetworkInterfaceBinding struct {
	Name  string `json:"name"`
	Model string `json:"model"`
}

// NetworkTopology is the manifest-level network contract, not an implementation.
type NetworkTopology struct {
	Mode       string                    `json:"mode"`
	Interfaces []NetworkInterfaceBinding `json:"interfaces"`
}

// DeviceBinding records requested topology without performing attachment.
type DeviceBinding struct {
	Kind           string `json:"kind"`
	HostReference  string `json:"host_reference"`
	GuestReference string `json:"guest_reference"`
	Required       bool   `json:"required"`
}

// WorkspaceBinding declares direct, fork, or guest-contained workspace semantics.
type WorkspaceBinding struct {
	Mode       string   `json:"mode"`
	References []string `json:"references"`
}

// SnapshotLineage binds optional ancestry without implementing snapshots.
type SnapshotLineage struct {
	ParentSnapshotID string `json:"parent_snapshot_id"`
	Generation       int    `json:"generation"`
}

// MachineManifest is the strict versioned technical recreation contract.
type MachineManifest struct {
	SchemaVersion            int                 `json:"schema_version"`
	MachineID                string              `json:"machine_id"`
	Name                     string              `json:"name"`
	Architecture             string              `json:"architecture"`
	VMM                      ComponentBinding    `json:"vmm"`
	Firmware                 ComponentBinding    `json:"firmware"`
	GuestImage               ComponentBinding    `json:"guest_image"`
	GuestAgentVersion        string              `json:"guest_agent_version"`
	CPU                      CPUConfiguration    `json:"cpu"`
	Memory                   MemoryConfiguration `json:"memory"`
	Disks                    []DiskBinding       `json:"disks"`
	Network                  NetworkTopology     `json:"network"`
	Devices                  []DeviceBinding     `json:"devices"`
	CapabilityPacks          []string            `json:"capability_packs"`
	Workspace                WorkspaceBinding    `json:"workspace"`
	SnapshotLineage          SnapshotLineage     `json:"snapshot_lineage"`
	RequiredHostCapabilities []string            `json:"required_host_capabilities"`
	CreatingReleaseID        string              `json:"creating_release_id"`
}

// BuildTarget binds a release to one operating system and architecture.
type BuildTarget struct {
	OS   string `json:"os"`
	Arch string `json:"arch"`
}

// GoToolchainIdentity binds the release build to the pinned official archive.
type GoToolchainIdentity struct {
	Version       string `json:"version"`
	ArchiveSHA256 string `json:"archive_sha256"`
}

// ReleaseComponent binds a future or current bundled component by version and digest.
type ReleaseComponent struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Digest  string `json:"digest"`
}

// BuildProvenance is standalone and contains no private-service requirement.
type BuildProvenance struct {
	BuilderKind     string `json:"builder_kind"`
	SourceDateEpoch int64  `json:"source_date_epoch"`
	Reproducible    bool   `json:"reproducible"`
}

// ReleaseManifest binds source, build, component, registry, and compatibility identities.
type ReleaseManifest struct {
	SchemaVersion        int                 `json:"schema_version"`
	ReleaseID            string              `json:"release_id"`
	ProductVersion       string              `json:"product_version"`
	SourceCommit         string              `json:"source_commit"`
	SourceTree           string              `json:"source_tree"`
	BuildMode            string              `json:"build_mode"`
	Target               BuildTarget         `json:"target"`
	GoToolchain          GoToolchainIdentity `json:"go_toolchain"`
	RegistryDigest       string              `json:"registry_digest"`
	BinaryDigest         string              `json:"binary_digest"`
	Components           []ReleaseComponent  `json:"components"`
	Compatibility        map[string]int      `json:"compatibility"`
	DependencyLockDigest string              `json:"dependency_lock_digest"`
	GuestCompatibility   []string            `json:"guest_compatibility"`
	VMMCompatibility     []string            `json:"vmm_compatibility"`
	Provenance           BuildProvenance     `json:"provenance"`
}

// ParseMachineManifest rejects unknown fields and validates every required binding.
func ParseMachineManifest(data []byte) (MachineManifest, error) {
	var manifest MachineManifest
	if err := DecodeStrict(data, &manifest); err != nil {
		return MachineManifest{}, err
	}
	if err := manifest.Validate(); err != nil {
		return MachineManifest{}, err
	}
	return manifest, nil
}

// Validate checks the machine recreation contract without creating a machine.
func (manifest MachineManifest) Validate() error {
	if manifest.SchemaVersion != 1 {
		return fmt.Errorf("unsupported machine manifest version %d", manifest.SchemaVersion)
	}
	if _, err := ParseIdentifier(MachineIDKind, manifest.MachineID); err != nil {
		return err
	}
	if !machineNamePattern.MatchString(manifest.Name) {
		return fmt.Errorf("invalid machine name %q", manifest.Name)
	}
	if manifest.Architecture != "x86_64" && manifest.Architecture != "aarch64" {
		return fmt.Errorf("unsupported machine architecture %q", manifest.Architecture)
	}
	components := []struct {
		label     string
		component ComponentBinding
	}{
		{"vmm", manifest.VMM},
		{"firmware", manifest.Firmware},
		{"guest_image", manifest.GuestImage},
	}
	for _, item := range components {
		if err := validateComponent(item.label, item.component); err != nil {
			return err
		}
	}
	if manifest.GuestAgentVersion == "" {
		return fmt.Errorf("guest agent version is required")
	}
	if manifest.CPU.VCPUs < 1 || manifest.CPU.VCPUs > 1024 {
		return fmt.Errorf("vCPU count must be between 1 and 1024")
	}
	if manifest.CPU.Mode != "generic" && manifest.CPU.Mode != "host" {
		return fmt.Errorf("invalid CPU mode %q", manifest.CPU.Mode)
	}
	const mebibyte = uint64(1024 * 1024)
	if manifest.Memory.Bytes < 128*mebibyte || manifest.Memory.Bytes%mebibyte != 0 {
		return fmt.Errorf("memory bytes must be at least 128 MiB and MiB-aligned")
	}
	if len(manifest.Disks) == 0 {
		return fmt.Errorf("at least one explicit disk is required")
	}
	diskIDs := make(map[string]bool, len(manifest.Disks))
	rootDisks := 0
	for index, disk := range manifest.Disks {
		if !objectNamePattern.MatchString(disk.ID) || diskIDs[disk.ID] {
			return fmt.Errorf("disk %d: invalid or duplicate ID %q", index, disk.ID)
		}
		diskIDs[disk.ID] = true
		if disk.Role != "root" && disk.Role != "data" {
			return fmt.Errorf("disk %q: invalid role %q", disk.ID, disk.Role)
		}
		if disk.Role == "root" {
			rootDisks++
		}
		if disk.Format != "raw" && disk.Format != "qcow2" {
			return fmt.Errorf("disk %q: missing or unknown explicit format %q", disk.ID, disk.Format)
		}
		if !sha256Pattern.MatchString(disk.BaseDigest) || !objectNamePattern.MatchString(disk.OverlayID) {
			return fmt.Errorf("disk %q: invalid base digest or overlay identity", disk.ID)
		}
	}
	if rootDisks != 1 {
		return fmt.Errorf("machine manifest must contain exactly one root disk")
	}
	if manifest.Network.Mode != "automatic_nat" && manifest.Network.Mode != "none" && manifest.Network.Mode != "custom" {
		return fmt.Errorf("invalid network mode %q", manifest.Network.Mode)
	}
	if manifest.Network.Mode == "none" && len(manifest.Network.Interfaces) != 0 {
		return fmt.Errorf("network mode none forbids interfaces")
	}
	if manifest.Network.Mode != "none" && len(manifest.Network.Interfaces) == 0 {
		return fmt.Errorf("active network modes require at least one interface")
	}
	interfaceNames := make(map[string]bool, len(manifest.Network.Interfaces))
	for _, iface := range manifest.Network.Interfaces {
		if !objectNamePattern.MatchString(iface.Name) || interfaceNames[iface.Name] || (iface.Model != "virtio" && iface.Model != "none") {
			return fmt.Errorf("invalid or duplicate network interface binding")
		}
		interfaceNames[iface.Name] = true
	}
	for _, device := range manifest.Devices {
		if !objectNamePattern.MatchString(device.Kind) || device.HostReference == "" || device.GuestReference == "" {
			return fmt.Errorf("invalid device topology binding")
		}
	}
	seenPacks := make(map[string]bool, len(manifest.CapabilityPacks))
	for _, pack := range manifest.CapabilityPacks {
		if _, err := ParseIdentifier(CapabilityPackIDKind, pack); err != nil {
			return err
		}
		if seenPacks[pack] {
			return fmt.Errorf("duplicate capability pack %q", pack)
		}
		seenPacks[pack] = true
	}
	if manifest.Workspace.Mode != "direct" && manifest.Workspace.Mode != "fork" && manifest.Workspace.Mode != "contained" {
		return fmt.Errorf("invalid workspace mode %q", manifest.Workspace.Mode)
	}
	for _, reference := range manifest.Workspace.References {
		if reference == "" || strings.ContainsRune(reference, '\x00') {
			return fmt.Errorf("invalid workspace reference")
		}
	}
	if manifest.SnapshotLineage.Generation < 0 {
		return fmt.Errorf("snapshot generation cannot be negative")
	}
	if manifest.SnapshotLineage.ParentSnapshotID != "" {
		if _, err := ParseIdentifier(SnapshotIDKind, manifest.SnapshotLineage.ParentSnapshotID); err != nil {
			return err
		}
		if manifest.SnapshotLineage.Generation == 0 {
			return fmt.Errorf("snapshot parent requires a positive generation")
		}
	} else if manifest.SnapshotLineage.Generation != 0 {
		return fmt.Errorf("positive snapshot generation requires a parent snapshot")
	}
	if err := validateUniqueNames("required host capability", manifest.RequiredHostCapabilities); err != nil {
		return err
	}
	if _, err := ParseIdentifier(ReleaseIDKind, manifest.CreatingReleaseID); err != nil {
		return err
	}
	return nil
}

// ParseReleaseManifest rejects unknown fields and verifies exact source and component identities.
func ParseReleaseManifest(data []byte) (ReleaseManifest, error) {
	var manifest ReleaseManifest
	if err := DecodeStrict(data, &manifest); err != nil {
		return ReleaseManifest{}, err
	}
	if err := manifest.Validate(); err != nil {
		return ReleaseManifest{}, err
	}
	return manifest, nil
}

// Validate checks the release compatibility contract without installing a release.
func (manifest ReleaseManifest) Validate() error {
	if manifest.SchemaVersion != 1 {
		return fmt.Errorf("unsupported release manifest version %d", manifest.SchemaVersion)
	}
	if _, err := ParseIdentifier(ReleaseIDKind, manifest.ReleaseID); err != nil {
		return err
	}
	if !productVersionRegex.MatchString(manifest.ProductVersion) {
		return fmt.Errorf("invalid product version %q", manifest.ProductVersion)
	}
	if !gitObjectPattern.MatchString(manifest.SourceCommit) || !gitObjectPattern.MatchString(manifest.SourceTree) {
		return fmt.Errorf("source commit and tree must be exact 40-character lowercase Git object IDs")
	}
	switch manifest.BuildMode {
	case "development", "fast", "sovereign":
	default:
		return fmt.Errorf("invalid build mode %q", manifest.BuildMode)
	}
	if manifest.Target.OS != "linux" || (manifest.Target.Arch != "amd64" && manifest.Target.Arch != "arm64") {
		return fmt.Errorf("unsupported build target %s/%s", manifest.Target.OS, manifest.Target.Arch)
	}
	if manifest.GoToolchain.Version == "" || !sha256Pattern.MatchString(manifest.GoToolchain.ArchiveSHA256) {
		return fmt.Errorf("invalid Go toolchain identity")
	}
	digests := []struct {
		label  string
		digest string
	}{
		{"registry", manifest.RegistryDigest},
		{"binary", manifest.BinaryDigest},
		{"dependency lock", manifest.DependencyLockDigest},
	}
	for _, item := range digests {
		if !sha256Pattern.MatchString(item.digest) {
			return fmt.Errorf("invalid %s digest", item.label)
		}
	}
	componentNames := make(map[string]bool, len(manifest.Components))
	for _, component := range manifest.Components {
		if !objectNamePattern.MatchString(component.Name) || component.Version == "" || !sha256Pattern.MatchString(component.Digest) || componentNames[component.Name] {
			return fmt.Errorf("invalid or duplicate release component %q", component.Name)
		}
		componentNames[component.Name] = true
	}
	required := make(map[string]bool, len(requiredCompatibilityNames))
	for _, name := range requiredCompatibilityNames {
		required[name] = true
	}
	if len(manifest.Compatibility) != len(required) {
		return fmt.Errorf("release compatibility set is incomplete")
	}
	for name, version := range manifest.Compatibility {
		if !required[name] || version != 1 {
			return fmt.Errorf("invalid release compatibility %q version %d", name, version)
		}
	}
	if len(manifest.GuestCompatibility) == 0 || len(manifest.VMMCompatibility) == 0 {
		return fmt.Errorf("guest and VMM compatibility metadata are required")
	}
	if manifest.Provenance.BuilderKind != "local_reproducible" || manifest.Provenance.SourceDateEpoch <= 0 || !manifest.Provenance.Reproducible {
		return fmt.Errorf("release provenance must declare a reproducible local build")
	}
	return nil
}

func validateComponent(label string, component ComponentBinding) error {
	if !objectNamePattern.MatchString(component.Provider) || component.Version == "" || !sha256Pattern.MatchString(component.Digest) {
		return fmt.Errorf("invalid %s component binding", label)
	}
	return nil
}

func validateUniqueNames(label string, names []string) error {
	seen := make(map[string]bool, len(names))
	for _, name := range names {
		if !objectNamePattern.MatchString(name) || seen[name] {
			return fmt.Errorf("invalid or duplicate %s %q", label, name)
		}
		seen[name] = true
	}
	return nil
}

// SortedCompatibilityNames exposes the frozen set for schema generation and tests.
func SortedCompatibilityNames() []string {
	result := append([]string(nil), requiredCompatibilityNames...)
	sort.Strings(result)
	return result
}
