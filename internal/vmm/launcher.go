// Package vmm owns the narrow Cloud Hypervisor process boundary used by
// EHJINT. It launches the pinned VMM through the same EHJINT binary so
// privilege reduction occurs immediately before exec without a shell.
package vmm

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"syscall"

	"github.com/StealthEyeLLC/ehjint/internal/chapi"
	"github.com/StealthEyeLLC/ehjint/internal/contracts"
	"golang.org/x/sys/unix"
)

const (
	maxLaunchSpec   = 64 * 1024
	launchSpecSeals = unix.F_SEAL_SEAL | unix.F_SEAL_SHRINK | unix.F_SEAL_GROW | unix.F_SEAL_WRITE
)

var launcherEnvironment = []string{"HOME=/nonexistent", "LANG=C", "LC_ALL=C", "RUST_BACKTRACE=0"}

// LaunchSpec is passed only through an immutable sealed memfd from the root
// controller to the root internal launcher. It contains no shell text,
// arbitrary argv, or arbitrary environment.
type LaunchSpec struct {
	SchemaVersion     int      `json:"schema_version"`
	BinaryPath        string   `json:"binary_path"`
	BinarySHA256      string   `json:"binary_sha256"`
	UID               uint32   `json:"uid"`
	GID               uint32   `json:"gid"`
	OperatorUID       uint32   `json:"operator_uid"`
	KVMGID            uint32   `json:"kvm_gid"`
	SupplementaryGIDs []uint32 `json:"supplementary_gids"`
	WorkingDirectory  string   `json:"working_directory"`
	APISocket         string   `json:"api_socket"`
	EventMonitor      string   `json:"event_monitor"`
	LogFile           string   `json:"log_file"`
}

// RunLauncher reads one strict immutable spec, removes all capabilities, sets
// the exact machine identity, enables no_new_privs, proves KVM access, and
// replaces itself with the pinned Cloud Hypervisor binary. It never invokes a
// shell and deliberately sets no parent-death signal.
func RunLauncher(specFD int) error {
	if os.Geteuid() != 0 || os.Getegid() != 0 {
		return fmt.Errorf("internal VMM launcher requires root identity")
	}
	spec, err := readSealedLaunchSpec(specFD)
	if err != nil {
		return err
	}
	if err := spec.Validate(); err != nil {
		return err
	}
	if err := verifyExecutable(spec.BinaryPath, spec.BinarySHA256); err != nil {
		return err
	}
	if err := validateWorkingDirectory(spec.WorkingDirectory, spec.UID, spec.GID); err != nil {
		return err
	}
	if err := validateKVMDevice(spec.KVMGID); err != nil {
		return err
	}
	if err := os.Chdir(spec.WorkingDirectory); err != nil {
		return fmt.Errorf("enter verified VMM runtime directory before privilege reduction: %w", err)
	}

	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	syscall.Umask(0o077)
	if err := unix.Prctl(unix.PR_CAP_AMBIENT, unix.PR_CAP_AMBIENT_CLEAR_ALL, 0, 0, 0); err != nil {
		return fmt.Errorf("clear VMM ambient capabilities: %w", err)
	}
	if err := dropBoundingCapabilities(); err != nil {
		return err
	}
	groups := []int{int(spec.KVMGID)}
	if err := unix.Setgroups(groups); err != nil {
		return fmt.Errorf("set VMM supplementary groups: %w", err)
	}
	if err := unix.Setresgid(int(spec.GID), int(spec.GID), int(spec.GID)); err != nil {
		return fmt.Errorf("set VMM GID: %w", err)
	}
	if err := unix.Setresuid(int(spec.UID), int(spec.UID), int(spec.UID)); err != nil {
		return fmt.Errorf("set VMM UID: %w", err)
	}
	if err := clearCapabilitySets(); err != nil {
		return err
	}
	if err := unix.Prctl(unix.PR_CAP_AMBIENT, unix.PR_CAP_AMBIENT_CLEAR_ALL, 0, 0, 0); err != nil {
		return fmt.Errorf("re-clear VMM ambient capabilities: %w", err)
	}
	if err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
		return fmt.Errorf("set VMM no_new_privs: %w", err)
	}
	if err := verifyDroppedIdentity(spec); err != nil {
		return err
	}
	kvmFD, err := unix.Open("/dev/kvm", unix.O_RDWR|unix.O_CLOEXEC, 0)
	if err != nil {
		return fmt.Errorf("open /dev/kvm after VMM privilege drop: %w", err)
	}
	if err := unix.Close(kvmFD); err != nil {
		return fmt.Errorf("close /dev/kvm proof descriptor: %w", err)
	}
	argv := []string{
		spec.BinaryPath,
		"--api-socket", "path=" + filepath.Base(spec.APISocket),
		"--event-monitor", "path=" + filepath.Base(spec.EventMonitor),
		"--log-file", filepath.Base(spec.LogFile),
		"--seccomp", "true",
	}
	return unix.Exec(spec.BinaryPath, argv, append([]string(nil), launcherEnvironment...))
}

func readSealedLaunchSpec(specFD int) (LaunchSpec, error) {
	if specFD < 3 || specFD > 1024 {
		return LaunchSpec{}, fmt.Errorf("invalid VMM launch-spec descriptor")
	}
	seals, err := unix.FcntlInt(uintptr(specFD), unix.F_GET_SEALS, 0)
	if err != nil {
		return LaunchSpec{}, fmt.Errorf("inspect VMM launch-spec seals: %w", err)
	}
	if seals&launchSpecSeals != launchSpecSeals {
		return LaunchSpec{}, fmt.Errorf("VMM launch spec is not immutable and sealed")
	}
	var stat unix.Stat_t
	if err := unix.Fstat(specFD, &stat); err != nil {
		return LaunchSpec{}, fmt.Errorf("inspect VMM launch-spec descriptor: %w", err)
	}
	if stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Size <= 0 || stat.Size > maxLaunchSpec {
		return LaunchSpec{}, fmt.Errorf("VMM launch spec is empty, oversized, or not a regular sealed object")
	}
	if _, err := unix.Seek(specFD, 0, io.SeekStart); err != nil {
		return LaunchSpec{}, fmt.Errorf("rewind VMM launch spec: %w", err)
	}
	file := os.NewFile(uintptr(specFD), "ehjint-vmm-launch-spec")
	if file == nil {
		return LaunchSpec{}, fmt.Errorf("open VMM launch-spec descriptor")
	}
	encoded, err := io.ReadAll(io.LimitReader(file, maxLaunchSpec+1))
	closeErr := file.Close()
	if err != nil {
		return LaunchSpec{}, fmt.Errorf("read VMM launch spec: %w", err)
	}
	if closeErr != nil {
		return LaunchSpec{}, fmt.Errorf("close VMM launch spec: %w", closeErr)
	}
	if len(encoded) == 0 || len(encoded) > maxLaunchSpec {
		return LaunchSpec{}, fmt.Errorf("VMM launch spec is empty or exceeds bound")
	}
	var spec LaunchSpec
	if err := contracts.DecodeStrict(encoded, &spec); err != nil {
		return LaunchSpec{}, fmt.Errorf("decode VMM launch spec: %w", err)
	}
	return spec, nil
}

func (spec LaunchSpec) Validate() error {
	if spec.SchemaVersion != 1 {
		return fmt.Errorf("unsupported VMM launch-spec version %d", spec.SchemaVersion)
	}
	if spec.BinarySHA256 != chapi.BinarySHA256 || !validSHA256(spec.BinarySHA256) {
		return fmt.Errorf("VMM binary digest does not identify pinned Cloud Hypervisor %s", chapi.ReleaseVersion)
	}
	if spec.UID == 0 || spec.GID == 0 {
		return fmt.Errorf("VMM target identity must be unprivileged")
	}
	if spec.OperatorUID != 0 && spec.UID == spec.OperatorUID {
		return fmt.Errorf("VMM target UID must differ from operator UID")
	}
	if spec.KVMGID == 0 || len(spec.SupplementaryGIDs) != 1 || spec.SupplementaryGIDs[0] != spec.KVMGID {
		return fmt.Errorf("VMM supplementary groups must contain only the required KVM group")
	}
	if !canonicalAbsolute(spec.BinaryPath) || !canonicalAbsolute(spec.WorkingDirectory) {
		return fmt.Errorf("VMM binary and working directory must be canonical absolute paths")
	}
	if err := validateRuntimeLeaf(spec.WorkingDirectory, spec.APISocket); err != nil {
		return fmt.Errorf("VMM API socket: %w", err)
	}
	if err := validateRuntimeLeaf(spec.WorkingDirectory, spec.EventMonitor); err != nil {
		return fmt.Errorf("VMM event monitor: %w", err)
	}
	if err := validateRuntimeLeaf(spec.WorkingDirectory, spec.LogFile); err != nil {
		return fmt.Errorf("VMM log file: %w", err)
	}
	if spec.APISocket == spec.EventMonitor || spec.APISocket == spec.LogFile || spec.EventMonitor == spec.LogFile {
		return fmt.Errorf("VMM runtime launch paths are duplicated")
	}
	return nil
}

func verifyExecutable(path, expectedDigest string) error {
	if !canonicalAbsolute(path) {
		return fmt.Errorf("VMM executable path is not canonical absolute")
	}
	if err := rejectSymlinkComponents(path); err != nil {
		return fmt.Errorf("VMM executable path: %w", err)
	}
	info, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("inspect VMM binary: %w", err)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != 0 {
		return fmt.Errorf("VMM binary must be owned by root")
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o111 == 0 || info.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf("VMM binary is not a safe executable regular file")
	}
	file, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("open VMM binary: %w", err)
	}
	defer file.Close()
	var magic [4]byte
	if _, err := io.ReadFull(file, magic[:]); err != nil || magic != [4]byte{0x7f, 'E', 'L', 'F'} {
		return fmt.Errorf("VMM binary is not ELF")
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return fmt.Errorf("rewind VMM binary: %w", err)
	}
	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return fmt.Errorf("hash VMM binary: %w", err)
	}
	if hex.EncodeToString(hash.Sum(nil)) != expectedDigest {
		return fmt.Errorf("VMM binary digest mismatch")
	}
	return nil
}

func validateWorkingDirectory(path string, uid, gid uint32) error {
	if !strings.HasPrefix(path, "/run/ehjint/") {
		return fmt.Errorf("VMM working directory is outside /run/ehjint")
	}
	if err := rejectSymlinkComponents(path); err != nil {
		return fmt.Errorf("VMM working directory: %w", err)
	}
	info, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("inspect VMM working directory: %w", err)
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0o700 {
		return fmt.Errorf("VMM working directory is not a private real directory")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != uid || stat.Gid != gid {
		return fmt.Errorf("VMM working directory owner does not match target identity")
	}
	parent := filepath.Dir(path)
	parentInfo, err := os.Lstat(parent)
	if err != nil {
		return fmt.Errorf("inspect VMM runtime parent: %w", err)
	}
	parentStat, ok := parentInfo.Sys().(*syscall.Stat_t)
	if !ok || !parentInfo.IsDir() || parentInfo.Mode()&os.ModeSymlink != 0 || parentInfo.Mode().Perm()&0o022 != 0 || parentStat.Uid != 0 {
		return fmt.Errorf("VMM runtime parent is not root-owned and non-writable by group/world")
	}
	return nil
}

func validateRuntimeLeaf(runtimeDir, path string) error {
	if !canonicalAbsolute(path) {
		return fmt.Errorf("path is not canonical absolute")
	}
	relative, err := filepath.Rel(runtimeDir, path)
	if err != nil || relative == "." || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) || filepath.IsAbs(relative) || strings.Contains(relative, string(filepath.Separator)) {
		return fmt.Errorf("path is not one direct child of the runtime directory")
	}
	return nil
}

func validateKVMDevice(kvmGID uint32) error {
	info, err := os.Lstat("/dev/kvm")
	if err != nil {
		return fmt.Errorf("inspect /dev/kvm: %w", err)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || info.Mode()&os.ModeDevice == 0 || info.Mode()&os.ModeCharDevice == 0 || info.Mode()&os.ModeSymlink != 0 || stat.Uid != 0 || stat.Gid != kvmGID || info.Mode().Perm()&0o007 != 0 {
		return fmt.Errorf("/dev/kvm ownership or mode does not match the declared narrow KVM group")
	}
	return nil
}

func dropBoundingCapabilities() error {
	encoded, err := os.ReadFile("/proc/sys/kernel/cap_last_cap")
	if err != nil {
		return fmt.Errorf("read kernel capability bound: %w", err)
	}
	var last int
	if _, err := fmt.Sscanf(strings.TrimSpace(string(encoded)), "%d", &last); err != nil || last < 0 || last > 1024 {
		return fmt.Errorf("parse kernel capability bound")
	}
	for capability := 0; capability <= last; capability++ {
		if err := unix.Prctl(unix.PR_CAPBSET_DROP, uintptr(capability), 0, 0, 0); err != nil {
			return fmt.Errorf("drop VMM bounding capability %d: %w", capability, err)
		}
	}
	return nil
}

func clearCapabilitySets() error {
	header := unix.CapUserHeader{Version: unix.LINUX_CAPABILITY_VERSION_3, Pid: 0}
	data := [2]unix.CapUserData{}
	if err := unix.Capset(&header, &data[0]); err != nil {
		return fmt.Errorf("clear VMM inheritable, permitted, and effective capabilities: %w", err)
	}
	return nil
}

func verifyDroppedIdentity(spec LaunchSpec) error {
	if unix.Getuid() != int(spec.UID) || unix.Geteuid() != int(spec.UID) || unix.Getgid() != int(spec.GID) || unix.Getegid() != int(spec.GID) {
		return fmt.Errorf("VMM identity did not converge after privilege drop")
	}
	actualGroups, err := unix.Getgroups()
	if err != nil {
		return fmt.Errorf("inspect VMM supplementary groups: %w", err)
	}
	sort.Ints(actualGroups)
	if len(actualGroups) != 1 || actualGroups[0] != int(spec.KVMGID) {
		return fmt.Errorf("VMM supplementary groups differ after privilege drop")
	}
	statusFile, err := os.Open("/proc/self/status")
	if err != nil {
		return fmt.Errorf("open post-drop VMM status: %w", err)
	}
	fields, parseErr := parseStatus(statusFile)
	closeErr := statusFile.Close()
	if parseErr != nil {
		return parseErr
	}
	if closeErr != nil {
		return fmt.Errorf("close post-drop VMM status: %w", closeErr)
	}
	if !fields.noNewPrivs || fields.capInh != 0 || fields.capPrm != 0 || fields.capEff != 0 || fields.capBnd != 0 || fields.capAmb != 0 {
		return fmt.Errorf("VMM privilege reduction did not converge")
	}
	return nil
}

func canonicalAbsolute(path string) bool {
	return path != "" && filepath.IsAbs(path) && filepath.Clean(path) == path && !strings.ContainsRune(path, '\x00')
}
