package vmm

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/StealthEyeLLC/ehjint/internal/chapi"
	"golang.org/x/sys/unix"
)

const (
	defaultStartupTimeout  = 10 * time.Second
	defaultShutdownTimeout = 5 * time.Second
	pidfdPollInterval      = 50 * time.Millisecond
)

// Paths are the complete VMM-owned runtime objects for one machine.
type Paths struct {
	RuntimeDir   string `json:"runtime_dir"`
	APISocket    string `json:"api_socket"`
	APILock      string `json:"api_lock"`
	VsockSocket  string `json:"vsock_socket"`
	EventMonitor string `json:"event_monitor"`
	LogFile      string `json:"log_file"`
	StdoutFile   string `json:"stdout_file"`
	StderrFile   string `json:"stderr_file"`
	LockFile     string `json:"lock_file"`
}

func DefaultPaths(runtimeDir string) Paths {
	return Paths{
		RuntimeDir:   runtimeDir,
		APISocket:    filepath.Join(runtimeDir, "api.sock"),
		APILock:      filepath.Join(runtimeDir, "api.sock.lock"),
		VsockSocket:  filepath.Join(runtimeDir, "vsock.sock"),
		EventMonitor: filepath.Join(runtimeDir, "vmm.events"),
		LogFile:      filepath.Join(runtimeDir, "vmm.log"),
		StdoutFile:   filepath.Join(runtimeDir, "vmm.stdout.log"),
		StderrFile:   filepath.Join(runtimeDir, "vmm.stderr.log"),
		LockFile:     filepath.Join(runtimeDir, "vmm.lock"),
	}
}

// SocketIdentity records exact ownership and mode of the private API socket.
type SocketIdentity struct {
	Path string `json:"path"`
	UID  uint32 `json:"uid"`
	GID  uint32 `json:"gid"`
	Mode uint32 `json:"mode"`
}

// VMMIdentity is durable expected state for restart-safe adoption.
type VMMIdentity struct {
	Process           ProcessIdentity `json:"process"`
	APISocket         SocketIdentity  `json:"api_socket"`
	APIPID            int64           `json:"api_pid"`
	BuildVersion      string          `json:"build_version"`
	RuntimeAPIVersion string          `json:"runtime_api_version"`
	Features          []string        `json:"features"`
}

// StartSpec binds a new VMM process to exact binaries, identity, and paths.
type StartSpec struct {
	HelperPath        string        `json:"helper_path"`
	HelperSHA256      string        `json:"helper_sha256"`
	BinaryPath        string        `json:"binary_path"`
	BinarySHA256      string        `json:"binary_sha256"`
	UID               uint32        `json:"uid"`
	GID               uint32        `json:"gid"`
	OperatorUID       uint32        `json:"operator_uid"`
	KVMGID            uint32        `json:"kvm_gid"`
	SupplementaryGIDs []uint32      `json:"supplementary_gids"`
	Paths             Paths         `json:"paths"`
	StartupTimeout    time.Duration `json:"startup_timeout"`
}

// AdoptSpec contains only durable expected state and immutable runtime paths.
type AdoptSpec struct {
	Identity   VMMIdentity   `json:"identity"`
	Paths      Paths         `json:"paths"`
	APITimeout time.Duration `json:"api_timeout"`
}

// Process is one verified Cloud Hypervisor process handle. wait is populated
// only when this controller launched the child; adopted processes are observed
// through pidfd and exact API identity.
type Process struct {
	Identity VMMIdentity
	Client   *chapi.Client
	Paths    Paths
	wait     <-chan error
	closeOne sync.Once
	closeErr error
}

type ShutdownOutcome string

const (
	ShutdownGracefulAPI ShutdownOutcome = "graceful-api"
	ShutdownSIGTERM     ShutdownOutcome = "sigterm"
	ShutdownSIGKILL     ShutdownOutcome = "sigkill"
	ShutdownAlreadyGone ShutdownOutcome = "already-absent"
)

type ShutdownResult struct {
	Outcome  ShutdownOutcome `json:"outcome"`
	APIError string          `json:"api_error,omitempty"`
}

// Start launches Cloud Hypervisor through the privilege-dropping same-binary
// EHJINT helper, then verifies process, API, executable, privileges, and socket.
func Start(ctx context.Context, spec StartSpec) (*Process, error) {
	if os.Geteuid() != 0 {
		return nil, fmt.Errorf("VMM supervisor requires root")
	}
	if err := spec.Validate(); err != nil {
		return nil, err
	}
	if err := verifyExecutable(spec.HelperPath, spec.HelperSHA256); err != nil {
		return nil, fmt.Errorf("verify EHJINT launcher: %w", err)
	}
	if err := verifyExecutable(spec.BinaryPath, spec.BinarySHA256); err != nil {
		return nil, err
	}
	if err := validateKVMDevice(spec.KVMGID); err != nil {
		return nil, err
	}
	if err := validateNewRuntime(spec.Paths, spec.UID, spec.GID); err != nil {
		return nil, err
	}

	stdout, err := createOwnedFile(spec.Paths.StdoutFile, spec.UID, spec.GID)
	if err != nil {
		return nil, err
	}
	stderr, err := createOwnedFile(spec.Paths.StderrFile, spec.UID, spec.GID)
	if err != nil {
		_ = stdout.Close()
		_ = CleanupRuntime(spec.Paths, spec.UID, spec.GID)
		return nil, err
	}
	lock, err := createOwnedFile(spec.Paths.LockFile, spec.UID, spec.GID)
	if err != nil {
		_ = stdout.Close()
		_ = stderr.Close()
		_ = CleanupRuntime(spec.Paths, spec.UID, spec.GID)
		return nil, err
	}
	if err := lock.Close(); err != nil {
		_ = stdout.Close()
		_ = stderr.Close()
		_ = CleanupRuntime(spec.Paths, spec.UID, spec.GID)
		return nil, fmt.Errorf("close VMM lock file: %w", err)
	}

	launch := LaunchSpec{
		SchemaVersion:     1,
		BinaryPath:        spec.BinaryPath,
		BinarySHA256:      spec.BinarySHA256,
		UID:               spec.UID,
		GID:               spec.GID,
		OperatorUID:       spec.OperatorUID,
		KVMGID:            spec.KVMGID,
		SupplementaryGIDs: append([]uint32(nil), spec.SupplementaryGIDs...),
		WorkingDirectory:  spec.Paths.RuntimeDir,
		APISocket:         spec.Paths.APISocket,
		EventMonitor:      spec.Paths.EventMonitor,
		LogFile:           spec.Paths.LogFile,
	}
	if err := launch.Validate(); err != nil {
		_ = stdout.Close()
		_ = stderr.Close()
		_ = CleanupRuntime(spec.Paths, spec.UID, spec.GID)
		return nil, err
	}
	specFile, err := newSealedLaunchSpec(launch)
	if err != nil {
		_ = stdout.Close()
		_ = stderr.Close()
		_ = CleanupRuntime(spec.Paths, spec.UID, spec.GID)
		return nil, err
	}
	devNull, err := os.OpenFile("/dev/null", os.O_RDWR, 0)
	if err != nil {
		_ = specFile.Close()
		_ = stdout.Close()
		_ = stderr.Close()
		_ = CleanupRuntime(spec.Paths, spec.UID, spec.GID)
		return nil, fmt.Errorf("open /dev/null for VMM stdin: %w", err)
	}

	command := exec.Command(spec.HelperPath, "internal", "vmm-launch", "--spec-fd", "3")
	command.Env = []string{"HOME=/root", "LANG=C", "LC_ALL=C"}
	command.ExtraFiles = []*os.File{specFile}
	command.Stdin = devNull
	command.Stdout = stdout
	command.Stderr = stderr
	command.SysProcAttr = &syscall.SysProcAttr{Setsid: true, Pdeathsig: 0}
	if err := command.Start(); err != nil {
		_ = specFile.Close()
		_ = devNull.Close()
		_ = stdout.Close()
		_ = stderr.Close()
		_ = CleanupRuntime(spec.Paths, spec.UID, spec.GID)
		return nil, fmt.Errorf("start EHJINT VMM launcher: %w", err)
	}
	pid := command.Process.Pid
	_ = specFile.Close()
	_ = devNull.Close()
	_ = stdout.Close()
	_ = stderr.Close()

	childStart, childPIDFD, err := openStartedChild(pid)
	if err != nil {
		_ = command.Process.Kill()
		_, _ = command.Process.Wait()
		_ = CleanupRuntime(spec.Paths, spec.UID, spec.GID)
		return nil, err
	}
	wait := make(chan error, 1)
	go func() {
		wait <- command.Wait()
		close(wait)
	}()
	abort := func(reason error) (*Process, error) {
		_ = killExactStartedChild(pid, childStart, childPIDFD)
		select {
		case <-wait:
		case <-time.After(2 * time.Second):
		}
		_ = unix.Close(childPIDFD)
		if cleanupErr := CleanupRuntime(spec.Paths, spec.UID, spec.GID); cleanupErr != nil {
			return nil, errors.Join(reason, cleanupErr)
		}
		return nil, reason
	}

	timeout := spec.StartupTimeout
	if timeout <= 0 {
		timeout = defaultStartupTimeout
	}
	startupCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	var client *chapi.Client
	for client == nil {
		select {
		case waitErr := <-wait:
			diagnostic := readStartupDiagnostic(spec.Paths.StderrFile)
			if waitErr == nil {
				return abort(fmt.Errorf("Cloud Hypervisor exited before readiness%s", diagnostic))
			}
			return abort(fmt.Errorf("Cloud Hypervisor exited before readiness: %w%s", waitErr, diagnostic))
		case <-startupCtx.Done():
			return abort(fmt.Errorf("Cloud Hypervisor startup did not reach readiness: %w", startupCtx.Err()))
		default:
		}
		if info, statErr := os.Lstat(spec.Paths.APISocket); statErr == nil && info.Mode()&os.ModeSocket != 0 && info.Mode()&os.ModeSymlink == 0 {
			candidate, newErr := chapi.New(spec.Paths.APISocket, 500*time.Millisecond)
			if newErr == nil {
				if _, newErr = candidate.Ping(startupCtx); newErr == nil {
					client = candidate
					break
				}
			}
		}
		time.Sleep(20 * time.Millisecond)
	}

	observed, observedClient, err := observeVMM(context.Background(), pid, spec.BinaryPath, spec.BinarySHA256, spec.UID, spec.GID, spec.SupplementaryGIDs, spec.Paths, time.Second)
	if err != nil {
		return abort(err)
	}
	client = observedClient
	if err := writeRuntimeIdentity(spec.Paths.LockFile, observed); err != nil {
		_ = unix.Close(observed.Process.PIDFD)
		return abort(err)
	}
	_ = unix.Close(childPIDFD)
	return &Process{Identity: observed, Client: client, Paths: spec.Paths, wait: wait}, nil
}

// Adopt reconstructs a process handle from durable identity without trusting a
// stored PID alone. It performs no mutation and never signals on mismatch.
func Adopt(ctx context.Context, spec AdoptSpec) (*Process, error) {
	if os.Geteuid() != 0 {
		return nil, fmt.Errorf("VMM adoption requires root")
	}
	if err := spec.Validate(); err != nil {
		return nil, err
	}
	expected := spec.Identity
	if err := verifyExecutable(expected.Process.ExecutablePath, expected.Process.ExecutableSHA256); err != nil {
		return nil, err
	}
	if err := validateWorkingDirectory(spec.Paths.RuntimeDir, expected.Process.UID, expected.Process.GID); err != nil {
		return nil, err
	}
	timeout := spec.APITimeout
	if timeout <= 0 {
		timeout = time.Second
	}
	observed, client, err := observeVMM(ctx, expected.Process.PID, expected.Process.ExecutablePath, expected.Process.ExecutableSHA256, expected.Process.UID, expected.Process.GID, expected.Process.SupplementaryGIDs, spec.Paths, timeout)
	if err != nil {
		return nil, err
	}
	if err := observed.matchesDurable(expected); err != nil {
		_ = unix.Close(observed.Process.PIDFD)
		return nil, err
	}
	return &Process{Identity: observed, Client: client, Paths: spec.Paths}, nil
}

func (spec StartSpec) Validate() error {
	if !validSHA256(spec.HelperSHA256) || spec.BinarySHA256 != chapi.BinarySHA256 {
		return fmt.Errorf("VMM helper or pinned binary digest is invalid")
	}
	if spec.UID == 0 || spec.GID == 0 || spec.KVMGID == 0 {
		return fmt.Errorf("VMM target identity must be complete and unprivileged")
	}
	if spec.OperatorUID != 0 && spec.UID == spec.OperatorUID {
		return fmt.Errorf("VMM target UID must differ from operator UID")
	}
	if len(spec.SupplementaryGIDs) != 1 || spec.SupplementaryGIDs[0] != spec.KVMGID {
		return fmt.Errorf("VMM supplementary groups must contain only KVM access")
	}
	if !canonicalAbsolute(spec.HelperPath) || !canonicalAbsolute(spec.BinaryPath) {
		return fmt.Errorf("VMM helper and binary paths must be canonical absolute")
	}
	return validatePaths(spec.Paths)
}

func (spec AdoptSpec) Validate() error {
	if err := validatePaths(spec.Paths); err != nil {
		return err
	}
	identity := spec.Identity
	if identity.Process.PID <= 0 || identity.Process.StartTime == 0 || identity.Process.UID == 0 || identity.Process.GID == 0 {
		return fmt.Errorf("VMM durable adoption identity is incomplete or privileged")
	}
	if identity.Process.ExecutableSHA256 != chapi.BinarySHA256 || identity.BuildVersion != chapi.ReleaseVersion || identity.RuntimeAPIVersion != chapi.RuntimeAPIVersion || identity.APIPID != int64(identity.Process.PID) {
		return fmt.Errorf("VMM durable adoption identity is not pinned Cloud Hypervisor %s", chapi.ReleaseVersion)
	}
	if identity.APISocket.Path != spec.Paths.APISocket || identity.APISocket.UID != identity.Process.UID || identity.APISocket.GID != identity.Process.GID || identity.APISocket.Mode != 0o700 {
		return fmt.Errorf("VMM durable API socket identity is invalid")
	}
	if len(identity.Process.SupplementaryGIDs) != 1 {
		return fmt.Errorf("VMM durable supplementary-group identity is not narrow")
	}
	return nil
}

func (identity VMMIdentity) matchesDurable(expected VMMIdentity) error {
	if err := identity.Process.MatchesDurable(expected.Process); err != nil {
		return err
	}
	if identity.APISocket != expected.APISocket {
		return fmt.Errorf("VMM durable API socket identity mismatch")
	}
	if identity.APIPID != expected.APIPID {
		return fmt.Errorf("VMM durable API PID mismatch")
	}
	if identity.BuildVersion != expected.BuildVersion {
		return fmt.Errorf("VMM durable build version mismatch")
	}
	if identity.RuntimeAPIVersion != expected.RuntimeAPIVersion {
		return fmt.Errorf("VMM durable runtime API version mismatch")
	}
	if strings.Join(identity.Features, "\x00") != strings.Join(expected.Features, "\x00") {
		return fmt.Errorf("VMM durable feature identity mismatch")
	}
	return nil
}

func observeVMM(ctx context.Context, pid int, binaryPath, binaryDigest string, uid, gid uint32, groups []uint32, paths Paths, apiTimeout time.Duration) (VMMIdentity, *chapi.Client, error) {
	processIdentity, err := InspectProcess(pid)
	if err != nil {
		return VMMIdentity{}, nil, err
	}
	closeIdentity := true
	defer func() {
		if closeIdentity {
			_ = unix.Close(processIdentity.PIDFD)
		}
	}()
	if err := processIdentity.Validate(binaryPath, binaryDigest, uid, gid, groups); err != nil {
		return VMMIdentity{}, nil, err
	}
	socketIdentity, err := inspectSocketIdentity(paths.APISocket, uid, gid)
	if err != nil {
		return VMMIdentity{}, nil, err
	}
	client, err := chapi.New(paths.APISocket, apiTimeout)
	if err != nil {
		return VMMIdentity{}, nil, err
	}
	ping, err := client.Ping(ctx)
	if err != nil {
		return VMMIdentity{}, nil, err
	}
	if ping.PID != int64(pid) {
		return VMMIdentity{}, nil, fmt.Errorf("Cloud Hypervisor API PID %d does not match observed PID %d", ping.PID, pid)
	}
	identity := VMMIdentity{
		Process:           processIdentity,
		APISocket:         socketIdentity,
		APIPID:            ping.PID,
		BuildVersion:      ping.BuildVersion,
		RuntimeAPIVersion: ping.Version,
		Features:          append([]string(nil), ping.Features...),
	}
	closeIdentity = false
	return identity, client, nil
}

func inspectSocketIdentity(path string, uid, gid uint32) (SocketIdentity, error) {
	if err := validateOwnedRuntimeObject(path, uid, gid, os.ModeSocket, 0o700); err != nil {
		return SocketIdentity{}, err
	}
	info, err := os.Lstat(path)
	if err != nil {
		return SocketIdentity{}, err
	}
	stat := info.Sys().(*syscall.Stat_t)
	return SocketIdentity{Path: path, UID: stat.Uid, GID: stat.Gid, Mode: uint32(info.Mode().Perm())}, nil
}

func newSealedLaunchSpec(spec LaunchSpec) (*os.File, error) {
	encoded, err := json.Marshal(spec)
	if err != nil {
		return nil, fmt.Errorf("encode VMM launch spec: %w", err)
	}
	if len(encoded) == 0 || len(encoded) > maxLaunchSpec {
		return nil, fmt.Errorf("encoded VMM launch spec exceeds bound")
	}
	fd, err := unix.MemfdCreate("ehjint-vmm-launch-spec", unix.MFD_CLOEXEC|unix.MFD_ALLOW_SEALING)
	if err != nil {
		return nil, fmt.Errorf("create sealed VMM launch spec: %w", err)
	}
	file := os.NewFile(uintptr(fd), "ehjint-vmm-launch-spec")
	if file == nil {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("open sealed VMM launch spec")
	}
	fail := func(err error) (*os.File, error) {
		_ = file.Close()
		return nil, err
	}
	if _, err := file.Write(encoded); err != nil {
		return fail(fmt.Errorf("write sealed VMM launch spec: %w", err))
	}
	if err := file.Sync(); err != nil {
		return fail(fmt.Errorf("sync sealed VMM launch spec: %w", err))
	}
	if _, err := unix.FcntlInt(file.Fd(), unix.F_ADD_SEALS, launchSpecSeals); err != nil {
		return fail(fmt.Errorf("seal VMM launch spec: %w", err))
	}
	if _, err := file.Seek(0, 0); err != nil {
		return fail(fmt.Errorf("rewind sealed VMM launch spec: %w", err))
	}
	return file, nil
}

func validatePaths(paths Paths) error {
	if !canonicalAbsolute(paths.RuntimeDir) || !strings.HasPrefix(paths.RuntimeDir, "/run/ehjint/") {
		return fmt.Errorf("VMM runtime directory is not a canonical /run/ehjint child")
	}
	expected := DefaultPaths(paths.RuntimeDir)
	if paths != expected {
		return fmt.Errorf("VMM runtime filenames do not match the canonical layout")
	}
	return nil
}

func validateNewRuntime(paths Paths, uid, gid uint32) error {
	if err := validatePaths(paths); err != nil {
		return err
	}
	if err := validateWorkingDirectory(paths.RuntimeDir, uid, gid); err != nil {
		return err
	}
	entries, err := os.ReadDir(paths.RuntimeDir)
	if err != nil {
		return fmt.Errorf("read VMM runtime directory: %w", err)
	}
	if len(entries) != 0 {
		return fmt.Errorf("VMM runtime directory is not empty")
	}
	return nil
}

func createOwnedFile(path string, uid, gid uint32) (*os.File, error) {
	if err := rejectSymlinkComponents(path); err != nil {
		return nil, err
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, fmt.Errorf("create VMM runtime file %s: %w", path, err)
	}
	if err := file.Chown(int(uid), int(gid)); err != nil {
		_ = file.Close()
		_ = os.Remove(path)
		return nil, fmt.Errorf("chown VMM runtime file %s: %w", path, err)
	}
	return file, nil
}

func writeRuntimeIdentity(path string, identity VMMIdentity) error {
	encoded, err := json.Marshal(identity)
	if err != nil {
		return fmt.Errorf("encode VMM runtime identity: %w", err)
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_TRUNC, 0)
	if err != nil {
		return fmt.Errorf("open VMM lock identity: %w", err)
	}
	if _, err := file.Write(append(encoded, '\n')); err != nil {
		_ = file.Close()
		return fmt.Errorf("write VMM lock identity: %w", err)
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return fmt.Errorf("sync VMM lock identity: %w", err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("close VMM lock identity: %w", err)
	}
	return syncDirectory(filepath.Dir(path))
}

func openStartedChild(pid int) (uint64, int, error) {
	stat, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return 0, -1, fmt.Errorf("observe started VMM launcher: %w", err)
	}
	start, err := parseStartTime(string(stat))
	if err != nil {
		return 0, -1, err
	}
	pidfd, err := unix.PidfdOpen(pid, 0)
	if err != nil {
		return 0, -1, fmt.Errorf("open started VMM launcher pidfd: %w", err)
	}
	return start, pidfd, nil
}

func killExactStartedChild(pid int, start uint64, pidfd int) error {
	stat, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("revalidate started VMM child: %w", err)
	}
	observed, err := parseStartTime(string(stat))
	if err != nil || observed != start {
		return fmt.Errorf("refuse to signal VMM child after identity conflict")
	}
	if err := unix.PidfdSendSignal(pidfd, unix.SIGKILL, nil, 0); err != nil && err != unix.ESRCH {
		return fmt.Errorf("kill exact failed VMM child: %w", err)
	}
	return nil
}

// WaitExit waits for pidfd readiness, which remains correct for adopted
// processes and cannot be confused by PID reuse.
func (process *Process) WaitExit(ctx context.Context, timeout time.Duration) error {
	if process == nil || process.Identity.Process.PIDFD < 0 {
		return fmt.Errorf("VMM process handle is incomplete")
	}
	return waitPIDFD(ctx, process.Identity.Process.PIDFD, timeout, process.wait)
}

func waitPIDFD(ctx context.Context, pidfd int, timeout time.Duration, wait <-chan error) error {
	if timeout <= 0 {
		timeout = defaultShutdownTimeout
	}
	deadline := time.Now().Add(timeout)
	pollFDs := []unix.PollFd{{Fd: int32(pidfd), Events: unix.POLLIN}}
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		remaining := time.Until(deadline)
		if remaining <= 0 {
			return fmt.Errorf("Cloud Hypervisor exit wait timed out")
		}
		interval := pidfdPollInterval
		if remaining < interval {
			interval = remaining
		}
		ready, err := unix.Poll(pollFDs, max(1, int(interval.Milliseconds())))
		if err == unix.EINTR {
			continue
		}
		if err != nil {
			return fmt.Errorf("poll Cloud Hypervisor pidfd: %w", err)
		}
		if ready > 0 && pollFDs[0].Revents&(unix.POLLIN|unix.POLLHUP|unix.POLLERR) != 0 {
			if wait != nil {
				select {
				case <-wait:
				case <-time.After(time.Second):
					return fmt.Errorf("Cloud Hypervisor pidfd was ready before child wait completed")
				}
			}
			return nil
		}
	}
}

// ShutdownVerified revalidates exact process and API identity, requests the
// live-verified HTTP 200 empty-body vmm.shutdown route, proves exit through
// pidfd, and uses bounded exact-process signals only if graceful shutdown does
// not complete.
func (process *Process) ShutdownVerified(ctx context.Context, timeout time.Duration) (ShutdownResult, error) {
	if process == nil || process.Client == nil {
		return ShutdownResult{}, fmt.Errorf("VMM process is incomplete")
	}
	if exactProcessAbsent(process.Identity.Process.PID, process.Identity.Process.StartTime) {
		return ShutdownResult{Outcome: ShutdownAlreadyGone}, nil
	}
	fresh, client, err := process.revalidate(ctx)
	if err != nil {
		return ShutdownResult{}, fmt.Errorf("VMM shutdown identity conflict: %w", err)
	}
	_ = unix.Close(fresh.Process.PIDFD)
	apiErr := client.ShutdownVMM(ctx)
	grace := timeout
	if grace <= 0 {
		grace = defaultShutdownTimeout
	}
	if apiErr == nil {
		if err := process.WaitExit(ctx, grace); err == nil {
			if !waitExactProcessAbsence(process.Identity.Process.PID, process.Identity.Process.StartTime, grace) {
				return ShutdownResult{}, fmt.Errorf("Cloud Hypervisor pidfd exited but exact process remains")
			}
			return ShutdownResult{Outcome: ShutdownGracefulAPI}, nil
		}
	}

	fresh, _, err = process.revalidate(ctx)
	if err != nil {
		return ShutdownResult{}, fmt.Errorf("VMM fallback identity conflict: %w", err)
	}
	if err := unix.PidfdSendSignal(fresh.Process.PIDFD, unix.SIGTERM, nil, 0); err != nil {
		_ = unix.Close(fresh.Process.PIDFD)
		return ShutdownResult{}, fmt.Errorf("send exact VMM SIGTERM: %w", err)
	}
	_ = unix.Close(fresh.Process.PIDFD)
	if err := process.WaitExit(ctx, grace); err == nil && waitExactProcessAbsence(process.Identity.Process.PID, process.Identity.Process.StartTime, grace) {
		return ShutdownResult{Outcome: ShutdownSIGTERM, APIError: errorString(apiErr)}, nil
	}

	fresh, _, err = process.revalidate(ctx)
	if err != nil {
		return ShutdownResult{}, fmt.Errorf("VMM forced fallback identity conflict: %w", err)
	}
	if err := unix.PidfdSendSignal(fresh.Process.PIDFD, unix.SIGKILL, nil, 0); err != nil {
		_ = unix.Close(fresh.Process.PIDFD)
		return ShutdownResult{}, fmt.Errorf("send exact VMM SIGKILL: %w", err)
	}
	_ = unix.Close(fresh.Process.PIDFD)
	if err := process.WaitExit(ctx, grace); err != nil {
		return ShutdownResult{}, fmt.Errorf("VMM forced shutdown timed out: %w", err)
	}
	if !waitExactProcessAbsence(process.Identity.Process.PID, process.Identity.Process.StartTime, grace) {
		return ShutdownResult{}, fmt.Errorf("VMM forced shutdown exited but exact process remains")
	}
	return ShutdownResult{Outcome: ShutdownSIGKILL, APIError: errorString(apiErr)}, nil
}

func (process *Process) Shutdown(ctx context.Context, timeout time.Duration) error {
	_, err := process.ShutdownVerified(ctx, timeout)
	return err
}

func (process *Process) revalidate(ctx context.Context) (VMMIdentity, *chapi.Client, error) {
	expected := process.Identity
	observed, client, err := observeVMM(ctx, expected.Process.PID, expected.Process.ExecutablePath, expected.Process.ExecutableSHA256, expected.Process.UID, expected.Process.GID, expected.Process.SupplementaryGIDs, process.Paths, time.Second)
	if err != nil {
		return VMMIdentity{}, nil, err
	}
	if err := observed.matchesDurable(expected); err != nil {
		_ = unix.Close(observed.Process.PIDFD)
		return VMMIdentity{}, nil, err
	}
	return observed, client, nil
}

func waitExactProcessAbsence(pid int, start uint64, timeout time.Duration) bool {
	if timeout <= 0 {
		timeout = defaultShutdownTimeout
	}
	deadline := time.Now().Add(timeout)
	for {
		if exactProcessAbsent(pid, start) {
			return true
		}
		if time.Now().After(deadline) {
			return false
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func exactProcessAbsent(pid int, start uint64) bool {
	stat, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if errors.Is(err, os.ErrNotExist) {
		return true
	}
	if err != nil {
		return false
	}
	observed, err := parseStartTime(string(stat))
	return err == nil && observed != start
}

// CloseHandle releases only this controller's pidfd. It never signals the VMM.
func (process *Process) CloseHandle() error {
	if process == nil {
		return nil
	}
	process.closeOne.Do(func() {
		if process.Identity.Process.PIDFD >= 0 {
			process.closeErr = unix.Close(process.Identity.Process.PIDFD)
			process.Identity.Process.PIDFD = -1
		}
	})
	return process.closeErr
}

// CleanupRuntime removes only exact owned VMM runtime objects after proving no
// live process has the runtime directory as cwd or an open descriptor. It never
// recursively deletes.
func CleanupRuntime(paths Paths, uid, gid uint32) error {
	if err := validatePaths(paths); err != nil {
		return err
	}
	if _, err := os.Lstat(paths.RuntimeDir); errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err := validateWorkingDirectory(paths.RuntimeDir, uid, gid); err != nil {
		return err
	}
	if pid, found := liveRuntimeUser(paths.RuntimeDir); found {
		return fmt.Errorf("refuse VMM runtime cleanup while PID %d still owns runtime state", pid)
	}
	objects := runtimeObjects(paths)
	for _, object := range objects {
		if _, err := os.Lstat(object.path); errors.Is(err, os.ErrNotExist) {
			continue
		} else if err != nil {
			return fmt.Errorf("inspect VMM runtime object %s: %w", object.path, err)
		}
		if err := validateOwnedRuntimeObject(object.path, uid, gid, object.typeMode, object.mode); err != nil {
			return err
		}
	}
	for _, object := range objects {
		if err := os.Remove(object.path); err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("remove VMM runtime object %s: %w", object.path, err)
		}
	}
	if err := syncDirectory(paths.RuntimeDir); err != nil {
		return err
	}
	entries, err := os.ReadDir(paths.RuntimeDir)
	if err != nil {
		return fmt.Errorf("re-read VMM runtime directory: %w", err)
	}
	if len(entries) != 0 {
		return fmt.Errorf("refuse to remove nonempty VMM runtime directory")
	}
	parent := filepath.Dir(paths.RuntimeDir)
	if err := os.Remove(paths.RuntimeDir); err != nil {
		return fmt.Errorf("remove empty VMM runtime directory: %w", err)
	}
	if err := syncDirectory(parent); err != nil {
		return err
	}
	for _, object := range objects {
		if _, err := os.Lstat(object.path); !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("VMM runtime object remains after cleanup: %s", object.path)
		}
	}
	if _, err := os.Lstat(paths.RuntimeDir); !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("VMM runtime directory remains after cleanup")
	}
	return nil
}

type runtimeObject struct {
	path     string
	typeMode os.FileMode
	mode     os.FileMode
}

func runtimeObjects(paths Paths) []runtimeObject {
	return []runtimeObject{
		{paths.APISocket, os.ModeSocket, 0o700},
		{paths.APILock, 0, 0o600},
		{paths.VsockSocket, os.ModeSocket, 0o700},
		{paths.EventMonitor, 0, 0o600},
		{paths.LogFile, 0, 0o600},
		{paths.StdoutFile, 0, 0o600},
		{paths.StderrFile, 0, 0o600},
		{paths.LockFile, 0, 0o600},
	}
}

func validateOwnedRuntimeObject(path string, uid, gid uint32, typeMode, mode os.FileMode) error {
	if err := rejectSymlinkComponents(path); err != nil {
		return err
	}
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 || info.Mode()&os.ModeType != typeMode || info.Mode().Perm() != mode.Perm() {
		return fmt.Errorf("VMM runtime object %s has invalid type or mode", path)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != uid || stat.Gid != gid {
		return fmt.Errorf("VMM runtime object %s owner mismatch", path)
	}
	return nil
}

func liveRuntimeUser(runtimeDir string) (int, bool) {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return 0, false
	}
	prefix := runtimeDir + string(filepath.Separator)
	for _, entry := range entries {
		pid, err := strconv.Atoi(entry.Name())
		if err != nil || pid <= 0 {
			continue
		}
		cwd, err := os.Readlink(filepath.Join("/proc", entry.Name(), "cwd"))
		if err == nil && (cwd == runtimeDir || strings.HasPrefix(cwd, prefix)) {
			return pid, true
		}
		fds, err := os.ReadDir(filepath.Join("/proc", entry.Name(), "fd"))
		if err != nil {
			continue
		}
		for _, fd := range fds {
			target, err := os.Readlink(filepath.Join("/proc", entry.Name(), "fd", fd.Name()))
			if err == nil && (target == runtimeDir || strings.HasPrefix(target, prefix)) {
				return pid, true
			}
		}
	}
	return 0, false
}

func syncDirectory(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("open directory for fsync %s: %w", path, err)
	}
	if err := directory.Sync(); err != nil {
		_ = directory.Close()
		return fmt.Errorf("fsync directory %s: %w", path, err)
	}
	if err := directory.Close(); err != nil {
		return fmt.Errorf("close synced directory %s: %w", path, err)
	}
	return nil
}

func validSHA256(value string) bool {
	if len(value) != 64 || value != strings.ToLower(value) {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}

func readStartupDiagnostic(path string) string {
	encoded, err := os.ReadFile(path)
	if err != nil || len(encoded) == 0 {
		return ""
	}
	const maximum = 4096
	if len(encoded) > maximum {
		encoded = encoded[len(encoded)-maximum:]
	}
	value := strings.TrimSpace(string(encoded))
	value = strings.Map(func(character rune) rune {
		if character == '\n' || character == '\r' || character == '\t' || (character >= 0x20 && character != 0x7f) {
			return character
		}
		return -1
	}, value)
	if value == "" {
		return ""
	}
	return ": " + value
}

func errorString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

func ParseSpecFD(value string) (int, error) {
	parsed, err := strconv.Atoi(value)
	if err != nil || parsed < 3 || parsed > 1024 {
		return 0, fmt.Errorf("invalid VMM launch-spec descriptor")
	}
	return parsed, nil
}
