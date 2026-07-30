package vmm

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/StealthEyeLLC/ehjint/internal/chapi"
	"golang.org/x/sys/unix"
)

const controllerRoleEnv = "EHJINT_VMM_CONTROLLER_ROLE"

type acceptanceReport struct {
	ReleaseVersion      string         `json:"release_version"`
	RuntimeAPIVersion   string         `json:"runtime_api_version"`
	TagCommit           string         `json:"tag_commit"`
	BinarySHA256        string         `json:"binary_sha256"`
	UID                 uint32         `json:"uid"`
	GID                 uint32         `json:"gid"`
	KVMGID              uint32         `json:"kvm_gid"`
	SupplementaryGIDs   []uint32       `json:"supplementary_gids"`
	KVMAccess           bool           `json:"kvm_access"`
	NoNewPrivs          bool           `json:"no_new_privs"`
	CapInheritable      uint64         `json:"cap_inheritable"`
	CapPermitted        uint64         `json:"cap_permitted"`
	CapEffective        uint64         `json:"cap_effective"`
	CapBounding         uint64         `json:"cap_bounding"`
	CapAmbient          uint64         `json:"cap_ambient"`
	SeccompMode         int            `json:"seccomp_mode"`
	SeccompFilters      int            `json:"seccomp_filters"`
	APISocketUID        uint32         `json:"api_socket_uid"`
	APISocketGID        uint32         `json:"api_socket_gid"`
	APISocketMode       uint32         `json:"api_socket_mode"`
	ObservedPID         int            `json:"observed_pid"`
	APIPID              int64          `json:"api_pid"`
	StartTime           uint64         `json:"start_time"`
	ExecutablePath      string         `json:"executable_path"`
	ExecutableSHA256    string         `json:"executable_sha256"`
	StartupCancellation bool           `json:"startup_cancellation"`
	ControllerKilled    bool           `json:"controller_killed"`
	ControllerLossAlive bool           `json:"controller_loss_alive"`
	AdoptionSucceeded   bool           `json:"adoption_succeeded"`
	DuplicateCount      int            `json:"duplicate_count"`
	NegativeAdoption    bool           `json:"negative_adoption"`
	NegativeError       string         `json:"negative_error"`
	Shutdown            ShutdownResult `json:"shutdown"`
	CleanupSucceeded    bool           `json:"cleanup_succeeded"`
	PositiveAbsence     bool           `json:"positive_absence"`
}

func TestVMMControllerProcess(t *testing.T) {
	role := os.Getenv(controllerRoleEnv)
	if role == "" {
		t.Skip("controller helper only")
	}
	input := os.Getenv("EHJINT_VMM_CONTROLLER_INPUT")
	output := os.Getenv("EHJINT_VMM_CONTROLLER_OUTPUT")
	if input == "" || output == "" {
		t.Fatal("controller helper paths missing")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	switch role {
	case "start-kill":
		var spec StartSpec
		readStrictJSON(t, input, &spec)
		startCtx, startCancel := context.WithCancel(ctx)
		process, err := Start(startCtx, spec)
		if err != nil {
			t.Fatal(err)
		}
		startCancel()
		if _, err := process.Client.Ping(context.Background()); err != nil {
			t.Fatalf("VMM died after startup context cancellation: %v", err)
		}
		writeJSONFile(t, output, process.Identity)
		if err := process.CloseHandle(); err != nil {
			t.Fatal(err)
		}
		if err := unix.Kill(os.Getpid(), unix.SIGKILL); err != nil {
			t.Fatal(err)
		}
		select {}
	case "adopt":
		var spec AdoptSpec
		readStrictJSON(t, input, &spec)
		process, err := Adopt(ctx, spec)
		if err != nil {
			t.Fatal(err)
		}
		writeJSONFile(t, output, process.Identity)
		if err := process.CloseHandle(); err != nil {
			t.Fatal(err)
		}
	default:
		t.Fatalf("unknown controller helper role %q", role)
	}
}

func TestRealPinnedControllerLossAdoption(t *testing.T) {
	if os.Getenv("EHJINT_VMM_ACCEPTANCE") != "1" {
		t.Skip("real pinned VMM acceptance disabled")
	}
	if os.Geteuid() != 0 {
		t.Fatal("real VMM acceptance requires root")
	}
	helper := requireEnv(t, "EHJINT_VMM_HELPER")
	binary := requireEnv(t, "EHJINT_VMM_BINARY")
	runtimeDir := requireEnv(t, "EHJINT_VMM_RUNTIME")
	reportPath := requireEnv(t, "EHJINT_VMM_REPORT")
	uid := parseEnvID(t, "EHJINT_VMM_UID")
	gid := parseEnvID(t, "EHJINT_VMM_GID")
	kvmGID := parseEnvID(t, "EHJINT_VMM_KVM_GID")
	if uid == 0 || gid == 0 || uid == uint32(os.Geteuid()) {
		t.Fatal("acceptance VMM identity is not dedicated and unprivileged")
	}
	if digest, err := hashPath(binary); err != nil || digest != chapi.BinarySHA256 {
		t.Fatalf("pinned binary identity: %s %v", digest, err)
	}
	helperDigest, err := hashPath(helper)
	if err != nil {
		t.Fatal(err)
	}
	paths := DefaultPaths(runtimeDir)
	base := StartSpec{HelperPath: helper, HelperSHA256: helperDigest, BinaryPath: binary, BinarySHA256: chapi.BinarySHA256, UID: uid, GID: gid, OperatorUID: uint32(os.Geteuid()), KVMGID: kvmGID, SupplementaryGIDs: []uint32{kvmGID}, Paths: paths, StartupTimeout: 10 * time.Second}

	cancelDir := runtimeDir + "-cancel"
	if err := os.Mkdir(cancelDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(cancelDir, int(uid), int(gid)); err != nil {
		t.Fatal(err)
	}
	cancelSpec := base
	cancelSpec.Paths = DefaultPaths(cancelDir)
	cancelCtx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := Start(cancelCtx, cancelSpec); err == nil || !errors.Is(err, context.Canceled) {
		t.Fatalf("startup cancellation result: %v", err)
	}
	if _, err := os.Lstat(cancelDir); !os.IsNotExist(err) {
		t.Fatalf("cancelled startup runtime remains: %v", err)
	}
	if count := countExactVMMs(t, binary, uid); count != 0 {
		t.Fatalf("cancelled startup left %d VMM processes", count)
	}

	work := t.TempDir()
	startInput, startOutput := filepath.Join(work, "start.json"), filepath.Join(work, "started.json")
	writeJSONFile(t, startInput, base)
	command := controllerCommand(t, "start-kill", startInput, startOutput)
	output, runErr := command.CombinedOutput()
	var exitError *exec.ExitError
	if !errors.As(runErr, &exitError) || exitError.ProcessState.Sys().(syscall.WaitStatus).Signal() != syscall.SIGKILL {
		t.Fatalf("starter was not abruptly SIGKILLed: %v: %s", runErr, output)
	}
	var durable VMMIdentity
	readStrictJSON(t, startOutput, &durable)
	if durable.Process.UID != uid || durable.Process.GID != gid || !reflectGroups(durable.Process.SupplementaryGIDs, []uint32{kvmGID}) {
		t.Fatalf("unexpected VMM identity: %+v", durable.Process)
	}
	observed, err := InspectProcess(durable.Process.PID)
	if err != nil {
		t.Fatalf("VMM did not survive controller loss: %v", err)
	}
	if err := observed.MatchesDurable(durable.Process); err != nil {
		_ = unix.Close(observed.PIDFD)
		t.Fatalf("post-loss process mismatch: %v", err)
	}
	_ = unix.Close(observed.PIDFD)
	client, err := chapi.New(paths.APISocket, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	ping, err := client.Ping(context.Background())
	if err != nil {
		t.Fatalf("post-loss API ping: %v", err)
	}
	if ping.PID != int64(durable.Process.PID) {
		t.Fatalf("post-loss API PID=%d process PID=%d", ping.PID, durable.Process.PID)
	}

	adoptInput, adoptOutput := filepath.Join(work, "adopt.json"), filepath.Join(work, "adopted.json")
	adoptSpec := AdoptSpec{Identity: durable, Paths: paths, APITimeout: time.Second}
	writeJSONFile(t, adoptInput, adoptSpec)
	adoptCommand := controllerCommand(t, "adopt", adoptInput, adoptOutput)
	if output, err := adoptCommand.CombinedOutput(); err != nil {
		t.Fatalf("new controller adoption: %v: %s", err, output)
	}
	var adoptedIdentity VMMIdentity
	readStrictJSON(t, adoptOutput, &adoptedIdentity)
	if err := adoptedIdentity.matchesDurable(durable); err != nil {
		t.Fatalf("adopted identity mismatch: %v", err)
	}
	duplicateCount := countExactVMMs(t, binary, uid)
	if duplicateCount != 1 {
		t.Fatalf("adoption produced %d matching VMMs", duplicateCount)
	}

	wrong := adoptSpec
	wrong.Identity = cloneAcceptanceIdentity(durable)
	wrong.Identity.Process.StartTime++
	_, negativeErr := Adopt(context.Background(), wrong)
	if negativeErr == nil {
		t.Fatal("wrong durable identity was adopted")
	}
	if exactProcessAbsent(durable.Process.PID, durable.Process.StartTime) {
		t.Fatal("negative adoption signaled the real process")
	}
	if _, err := os.Lstat(paths.APISocket); err != nil {
		t.Fatalf("negative adoption removed API socket: %v", err)
	}

	process, err := Adopt(context.Background(), adoptSpec)
	if err != nil {
		t.Fatal(err)
	}
	shutdown, err := process.ShutdownVerified(context.Background(), 5*time.Second)
	if err != nil {
		_ = process.CloseHandle()
		t.Fatal(err)
	}
	if shutdown.Outcome != ShutdownGracefulAPI {
		_ = process.CloseHandle()
		t.Fatalf("shutdown outcome=%+v", shutdown)
	}
	if err := process.CloseHandle(); err != nil {
		t.Fatal(err)
	}
	if err := CleanupRuntime(paths, uid, gid); err != nil {
		t.Fatal(err)
	}
	if !runtimeAbsent(paths) || !exactProcessAbsent(durable.Process.PID, durable.Process.StartTime) {
		t.Fatal("positive absence not established")
	}

	report := acceptanceReport{ReleaseVersion: chapi.ReleaseVersion, RuntimeAPIVersion: chapi.RuntimeAPIVersion, TagCommit: chapi.ReleaseTagCommit, BinarySHA256: chapi.BinarySHA256, UID: uid, GID: gid, KVMGID: kvmGID, SupplementaryGIDs: append([]uint32(nil), durable.Process.SupplementaryGIDs...), KVMAccess: true, NoNewPrivs: durable.Process.NoNewPrivs, CapInheritable: durable.Process.CapInheritable, CapPermitted: durable.Process.CapPermitted, CapEffective: durable.Process.CapEffective, CapBounding: durable.Process.CapBounding, CapAmbient: durable.Process.CapAmbient, SeccompMode: durable.Process.SeccompMode, SeccompFilters: durable.Process.SeccompFilters, APISocketUID: durable.APISocket.UID, APISocketGID: durable.APISocket.GID, APISocketMode: durable.APISocket.Mode, ObservedPID: durable.Process.PID, APIPID: durable.APIPID, StartTime: durable.Process.StartTime, ExecutablePath: durable.Process.ExecutablePath, ExecutableSHA256: durable.Process.ExecutableSHA256, StartupCancellation: true, ControllerKilled: true, ControllerLossAlive: true, AdoptionSucceeded: true, DuplicateCount: duplicateCount, NegativeAdoption: true, NegativeError: "process start identity mismatch", Shutdown: shutdown, CleanupSucceeded: true, PositiveAbsence: true}
	writeJSONFile(t, reportPath, report)
}

func controllerCommand(t *testing.T, role, input, output string) *exec.Cmd {
	t.Helper()
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	command := exec.Command(executable, "-test.run=^TestVMMControllerProcess$", "-test.count=1")
	command.Env = append(os.Environ(), controllerRoleEnv+"="+role, "EHJINT_VMM_CONTROLLER_INPUT="+input, "EHJINT_VMM_CONTROLLER_OUTPUT="+output)
	return command
}

func requireEnv(t *testing.T, name string) string {
	t.Helper()
	value := os.Getenv(name)
	if value == "" {
		t.Fatalf("%s is required", name)
	}
	return value
}
func parseEnvID(t *testing.T, name string) uint32 {
	t.Helper()
	parsed, err := strconv.ParseUint(requireEnv(t, name), 10, 32)
	if err != nil || parsed == 0 {
		t.Fatalf("invalid %s", name)
	}
	return uint32(parsed)
}

func readStrictJSON(t *testing.T, path string, destination any) {
	t.Helper()
	encoded, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	decoder := json.NewDecoder(strings.NewReader(string(encoded)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		t.Fatal(err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		t.Fatal("trailing JSON")
	}
}

func writeJSONFile(t *testing.T, path string, value any) {
	t.Helper()
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	encoded = append(encoded, '\n')
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	temporary := path + ".tmp-" + strconv.Itoa(os.Getpid())
	file, err := os.OpenFile(temporary, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := file.Write(encoded); err != nil {
		_ = file.Close()
		_ = os.Remove(temporary)
		t.Fatal(err)
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		_ = os.Remove(temporary)
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		_ = os.Remove(temporary)
		t.Fatal(err)
	}
	if err := os.Rename(temporary, path); err != nil {
		_ = os.Remove(temporary)
		t.Fatal(err)
	}
	if err := syncDirectory(filepath.Dir(path)); err != nil {
		t.Fatal(err)
	}
}

func reflectGroups(left, right []uint32) bool { return equalGroups(left, right) }

func cloneAcceptanceIdentity(identity VMMIdentity) VMMIdentity {
	identity.Process.SupplementaryGIDs = append([]uint32(nil), identity.Process.SupplementaryGIDs...)
	identity.Features = append([]string(nil), identity.Features...)
	return identity
}

func countExactVMMs(t *testing.T, binary string, uid uint32) int {
	t.Helper()
	entries, err := os.ReadDir("/proc")
	if err != nil {
		t.Fatal(err)
	}
	count := 0
	for _, entry := range entries {
		pid, err := strconv.Atoi(entry.Name())
		if err != nil || pid <= 0 {
			continue
		}
		executable, err := os.Readlink(filepath.Join("/proc", entry.Name(), "exe"))
		if err != nil || filepath.Clean(executable) != filepath.Clean(binary) {
			continue
		}
		identity, err := InspectProcess(pid)
		if err != nil {
			continue
		}
		if identity.RealUID == uid && identity.EffectiveUID == uid {
			count++
		}
		_ = unix.Close(identity.PIDFD)
	}
	return count
}

func runtimeAbsent(paths Paths) bool {
	for _, path := range []string{paths.APISocket, paths.APILock, paths.VsockSocket, paths.EventMonitor, paths.LogFile, paths.StdoutFile, paths.StderrFile, paths.LockFile, paths.RuntimeDir} {
		if _, err := os.Lstat(path); !os.IsNotExist(err) {
			return false
		}
	}
	return true
}
