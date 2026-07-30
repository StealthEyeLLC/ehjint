package chapi

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

const (
	ReleaseVersion      = "v53.0"
	RuntimeAPIVersion   = "53.0.0"
	ReleaseTagCommit    = "9ed824d6d08df3e96f7d5f50795d9449ac99f431"
	BinarySHA256        = "448af3d4e59b22c2987f7df94c213ad40fb53a10d437e42b5ee6c4fce7c29ecc"
	SourceArchiveSHA256 = "7d806fc1ee42dc4cf5af1293925ab0f741c676ccd29b7f1fa6cb798c01c51f1f"
	OpenAPISHA256       = "004e2d5ab70d9d95a1de3289a70ca116c7592da62765e009232c85506cd0e6c4"

	// These values appeared in the continuation handoff but do not match the official v53.0
	// GitHub release metadata or the byte-identical OpenAPI file in the official source archive.
	SupersededBinarySHA256  = "448af3d4b496500663ec0df75c30ff335801ca77282c55603f20eaeb532a8bb9"
	SupersededOpenAPISHA256 = "a4c07525e9e4296418cb839e3ef08ec7a86ee05bc23ad4c670ad1b2c91711a57"
	RejectedBinaryPrefix    = "b2c0"

	APIPrefix              = "/api/v1/"
	ExpectedBuildVersion   = ReleaseVersion
	ExpectedRuntimeVersion = RuntimeAPIVersion
)

var DefaultManagedRoots = []string{"/var/lib/ehjint", "/run/ehjint", "/etc/ehjint", "/opt/ehjint"}

type ImageType string

const (
	ImageTypeQcow2 ImageType = "Qcow2"
	ImageTypeRaw   ImageType = "Raw"
	ImageTypeQCOW2 ImageType = ImageTypeQcow2
)

type ConsoleMode string

const (
	ConsoleModeOff  ConsoleMode = "Off"
	ConsoleModePty  ConsoleMode = "Pty"
	ConsoleModeTty  ConsoleMode = "Tty"
	ConsoleModeFile ConsoleMode = "File"
	ConsoleModeNull ConsoleMode = "Null"
)

type LandlockAccess string

const (
	LandlockRead      LandlockAccess = "r"
	LandlockWrite     LandlockAccess = "w"
	LandlockReadWrite LandlockAccess = "rw"
)

type SeccompMode string

const SeccompEnabled SeccompMode = "true"

type PayloadConfig struct {
	Firmware  string `json:"firmware,omitempty"`
	Kernel    string `json:"kernel,omitempty"`
	Cmdline   string `json:"cmdline,omitempty"`
	Initramfs string `json:"initramfs,omitempty"`
}

type CPUConfig struct {
	BootVCPUs uint8 `json:"boot_vcpus"`
	MaxVCPUs  uint8 `json:"max_vcpus"`
}

type MemoryConfig struct {
	Size uint64 `json:"size"`
}

type DiskConfig struct {
	Path         string    `json:"path"`
	Readonly     bool      `json:"readonly"`
	Direct       bool      `json:"direct,omitempty"`
	NumQueues    uint16    `json:"num_queues"`
	QueueSize    uint16    `json:"queue_size"`
	ID           string    `json:"id,omitempty"`
	ImageType    ImageType `json:"image_type"`
	Sparse       bool      `json:"sparse,omitempty"`
	BackingFiles bool      `json:"backing_files,omitempty"`
}

type SerialConfig struct {
	Mode ConsoleMode `json:"mode"`
	File string      `json:"file,omitempty"`
}

type ConsoleConfig struct {
	Mode ConsoleMode `json:"mode"`
	File string      `json:"file,omitempty"`
}

type VsockConfig struct {
	CID    uint64 `json:"cid"`
	Socket string `json:"socket"`
	ID     string `json:"id,omitempty"`
}

type LandlockConfig struct {
	Path   string         `json:"path"`
	Access LandlockAccess `json:"access"`
}

type LandlockRule = LandlockConfig

// VMConfig is the intentionally narrow Cloud Hypervisor v53 configuration used by EHJINT.
// Net is mandatory and must be an explicit empty array. Seccomp is a launcher CLI setting,
// not a VM API field, and therefore deliberately does not appear in this structure.
type VMConfig struct {
	CPUs           CPUConfig        `json:"cpus"`
	Memory         MemoryConfig     `json:"memory"`
	Payload        PayloadConfig    `json:"payload"`
	Disks          []DiskConfig     `json:"disks"`
	Net            []any            `json:"net"`
	Serial         SerialConfig     `json:"serial"`
	Console        ConsoleConfig    `json:"console"`
	Vsock          *VsockConfig     `json:"vsock,omitempty"`
	Pvpanic        bool             `json:"pvpanic"`
	LandlockEnable bool             `json:"landlock_enable"`
	LandlockRules  []LandlockConfig `json:"landlock_rules"`
}

type VMMInfo struct {
	BuildVersion string   `json:"build_version"`
	Version      string   `json:"version"`
	PID          int64    `json:"pid"`
	Features     []string `json:"features"`
}

func (info VMMInfo) Validate() error {
	if info.BuildVersion != ReleaseVersion {
		return fmt.Errorf("Cloud Hypervisor pinned build version mismatch: got %q want %q", info.BuildVersion, ReleaseVersion)
	}
	if info.Version != RuntimeAPIVersion {
		return fmt.Errorf("Cloud Hypervisor pinned runtime API version mismatch: got %q want %q", info.Version, RuntimeAPIVersion)
	}
	if info.PID <= 0 {
		return fmt.Errorf("Cloud Hypervisor API PID is invalid")
	}
	return nil
}

type VMState string

const (
	VMStateCreated  VMState = "Created"
	VMStateRunning  VMState = "Running"
	VMStateShutdown VMState = "Shutdown"
	VMStatePaused   VMState = "Paused"
)

type VMInfo struct {
	Config           json.RawMessage            `json:"config"`
	State            VMState                    `json:"state"`
	MemoryActualSize *uint64                    `json:"memory_actual_size,omitempty"`
	DeviceTree       map[string]json.RawMessage `json:"device_tree,omitempty"`
}

func (info VMInfo) Validate() error {
	if len(info.Config) == 0 || info.Config[0] != '{' || !json.Valid(info.Config) {
		return fmt.Errorf("Cloud Hypervisor VM info config is invalid")
	}
	switch info.State {
	case VMStateCreated, VMStateRunning, VMStateShutdown, VMStatePaused:
	default:
		return fmt.Errorf("Cloud Hypervisor VM state is invalid")
	}
	return nil
}

func (config VMConfig) Validate() error {
	return config.validateWithRoots(DefaultManagedRoots)
}

func (config VMConfig) ValidateForRoots(managedRoots []string) error {
	return config.validateWithRoots(managedRoots)
}

func (config VMConfig) validateWithRoots(managedRoots []string) error {
	if err := validateManagedRoots(managedRoots); err != nil {
		return err
	}
	if config.CPUs.BootVCPUs == 0 || config.CPUs.MaxVCPUs == 0 || config.CPUs.BootVCPUs > config.CPUs.MaxVCPUs {
		return fmt.Errorf("Cloud Hypervisor CPU configuration is invalid")
	}
	if config.Memory.Size < 128<<20 || config.Memory.Size%4096 != 0 {
		return fmt.Errorf("Cloud Hypervisor memory size is invalid")
	}
	if (config.Payload.Firmware == "") == (config.Payload.Kernel == "") {
		return fmt.Errorf("exactly one Cloud Hypervisor firmware or kernel payload is required")
	}
	for _, path := range []string{config.Payload.Firmware, config.Payload.Kernel, config.Payload.Initramfs} {
		if path != "" {
			if err := validateManagedPath(path, managedRoots); err != nil {
				return fmt.Errorf("Cloud Hypervisor payload path: %w", err)
			}
		}
	}
	if len(config.Disks) == 0 {
		return fmt.Errorf("at least one Cloud Hypervisor disk is required")
	}
	seenDiskPath := make(map[string]struct{}, len(config.Disks))
	seenID := make(map[string]struct{}, len(config.Disks))
	for index, disk := range config.Disks {
		if err := validateManagedPath(disk.Path, managedRoots); err != nil {
			return fmt.Errorf("Cloud Hypervisor disk %d path: %w", index, err)
		}
		switch disk.ImageType {
		case ImageTypeQcow2, ImageTypeRaw:
		default:
			return fmt.Errorf("Cloud Hypervisor disk %d has missing or unsupported image_type %q", index, disk.ImageType)
		}
		if disk.NumQueues == 0 || disk.QueueSize == 0 {
			return fmt.Errorf("Cloud Hypervisor disk %d queue configuration is invalid", index)
		}
		if _, exists := seenDiskPath[disk.Path]; exists {
			return fmt.Errorf("Cloud Hypervisor disk path is duplicated")
		}
		seenDiskPath[disk.Path] = struct{}{}
		if disk.ID != "" {
			if _, exists := seenID[disk.ID]; exists {
				return fmt.Errorf("Cloud Hypervisor disk ID is duplicated")
			}
			seenID[disk.ID] = struct{}{}
		}
	}
	if config.Net == nil || len(config.Net) != 0 {
		return fmt.Errorf("Cloud Hypervisor networking must be an explicit empty array")
	}
	if err := validateConsole(&config.Serial, managedRoots); err != nil {
		return fmt.Errorf("Cloud Hypervisor serial: %w", err)
	}
	serial := SerialConfig{Mode: config.Console.Mode, File: config.Console.File}
	if err := validateConsole(&serial, managedRoots); err != nil {
		return fmt.Errorf("Cloud Hypervisor console: %w", err)
	}
	if config.Vsock == nil || config.Vsock.CID < 3 {
		return fmt.Errorf("Cloud Hypervisor vsock CID must be at least 3")
	}
	if err := validateManagedPath(config.Vsock.Socket, managedRoots); err != nil {
		return fmt.Errorf("Cloud Hypervisor vsock socket: %w", err)
	}
	if !config.LandlockEnable || len(config.LandlockRules) == 0 {
		return fmt.Errorf("Cloud Hypervisor Landlock must be enabled with explicit rules")
	}
	for index, rule := range config.LandlockRules {
		if err := validateManagedPath(rule.Path, managedRoots); err != nil {
			return fmt.Errorf("Cloud Hypervisor Landlock rule %d: %w", index, err)
		}
		switch rule.Access {
		case LandlockRead, LandlockWrite, LandlockReadWrite:
		default:
			return fmt.Errorf("Cloud Hypervisor Landlock rule %d has invalid access %q", index, rule.Access)
		}
	}
	return nil
}

// ValidateFilesystem adds host-truth checks to structural validation. Payloads and disks must
// be regular non-symlink files; Landlock rules must name existing non-symlink files or
// directories; the vsock parent must be an existing non-symlink directory.
func (config VMConfig) ValidateFilesystem(managedRoots []string) error {
	if err := config.validateWithRoots(managedRoots); err != nil {
		return err
	}
	for _, path := range []string{config.Payload.Firmware, config.Payload.Kernel, config.Payload.Initramfs} {
		if path != "" {
			if err := validateOwnedKind(path, managedRoots, true, false); err != nil {
				return fmt.Errorf("Cloud Hypervisor payload path %q: %w", path, err)
			}
		}
	}
	for _, disk := range config.Disks {
		if err := validateOwnedKind(disk.Path, managedRoots, true, false); err != nil {
			return fmt.Errorf("Cloud Hypervisor disk path %q: %w", disk.Path, err)
		}
	}
	if err := validateOwnedKind(filepath.Dir(config.Vsock.Socket), managedRoots, false, true); err != nil {
		return fmt.Errorf("Cloud Hypervisor vsock parent: %w", err)
	}
	if _, err := os.Lstat(config.Vsock.Socket); err == nil {
		return fmt.Errorf("Cloud Hypervisor vsock socket already exists")
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("inspect Cloud Hypervisor vsock socket: %w", err)
	}
	for _, rule := range config.LandlockRules {
		if err := validateOwnedKind(rule.Path, managedRoots, false, false); err != nil {
			return fmt.Errorf("Cloud Hypervisor Landlock path %q: %w", rule.Path, err)
		}
	}
	return nil
}

func validateConsole(config *SerialConfig, managedRoots []string) error {
	if config == nil {
		return nil
	}
	switch config.Mode {
	case ConsoleModeOff, ConsoleModePty, ConsoleModeTty, ConsoleModeNull:
		if config.File != "" {
			return fmt.Errorf("mode %q cannot have a file", config.Mode)
		}
	case ConsoleModeFile:
		if err := validateManagedPath(config.File, managedRoots); err != nil {
			return err
		}
	default:
		return fmt.Errorf("invalid mode %q", config.Mode)
	}
	return nil
}

func canonicalAbsolute(path string) bool {
	return path != "" && filepath.IsAbs(path) && filepath.Clean(path) == path && strings.IndexByte(path, 0) < 0
}

func validateManagedRoots(roots []string) error {
	if len(roots) == 0 {
		return fmt.Errorf("at least one EHJINT managed root is required")
	}
	for _, root := range roots {
		if root == "" || !filepath.IsAbs(root) || filepath.Clean(root) != root || root == string(filepath.Separator) {
			return fmt.Errorf("EHJINT managed root is invalid")
		}
	}
	return nil
}

func validateManagedPath(path string, roots []string) error {
	if path == "" || !filepath.IsAbs(path) || filepath.Clean(path) != path || strings.IndexByte(path, 0) >= 0 {
		return fmt.Errorf("path is not canonical absolute")
	}
	for _, root := range roots {
		relative, err := filepath.Rel(root, path)
		if err == nil && (relative == "." || (relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator)) && !filepath.IsAbs(relative))) {
			return nil
		}
	}
	return fmt.Errorf("path escapes declared EHJINT managed roots")
}

func validateOwnedKind(path string, roots []string, requireRegular, requireDirectory bool) error {
	if err := validateManagedPath(path, roots); err != nil {
		return err
	}
	if err := rejectSymlinkComponents(path); err != nil {
		return err
	}
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("symlink is not allowed")
	}
	if requireRegular && !info.Mode().IsRegular() {
		return fmt.Errorf("regular file is required")
	}
	if requireDirectory && !info.IsDir() {
		return fmt.Errorf("directory is required")
	}
	if !requireRegular && !requireDirectory && !info.Mode().IsRegular() && !info.IsDir() {
		return fmt.Errorf("regular file or directory is required")
	}
	return nil
}

func rejectSymlinkComponents(path string) error {
	clean := filepath.Clean(path)
	current := string(filepath.Separator)
	for _, part := range strings.Split(strings.TrimPrefix(clean, string(filepath.Separator)), string(filepath.Separator)) {
		if part == "" {
			continue
		}
		current = filepath.Join(current, part)
		info, err := os.Lstat(current)
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("inspect path component %q: %w", current, err)
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("symlink component %q is not allowed", current)
		}
	}
	return nil
}
