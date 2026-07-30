package vmm

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/StealthEyeLLC/ehjint/internal/chapi"
	"golang.org/x/sys/unix"
)

func baseLaunchSpec() LaunchSpec {
	dir := "/run/ehjint/machines/test-machine"
	return LaunchSpec{SchemaVersion: 1, BinaryPath: "/opt/ehjint/lib/cloud-hypervisor-v53.0", BinarySHA256: chapi.BinarySHA256, UID: 62001, GID: 62002, OperatorUID: 1000, KVMGID: 993, SupplementaryGIDs: []uint32{993}, WorkingDirectory: dir, APISocket: filepath.Join(dir, "api.sock"), EventMonitor: filepath.Join(dir, "vmm.events"), LogFile: filepath.Join(dir, "vmm.log")}
}

func cloneLaunchSpec(v LaunchSpec) LaunchSpec {
	v.SupplementaryGIDs = append([]uint32(nil), v.SupplementaryGIDs...)
	return v
}

func TestLaunchSpecRejectsPrivilegeAndPathExpansion(t *testing.T) {
	base := baseLaunchSpec()
	if err := base.Validate(); err != nil {
		t.Fatalf("valid launch spec rejected: %v", err)
	}
	cases := map[string]func(*LaunchSpec){
		"schema": func(v *LaunchSpec) { v.SchemaVersion = 2 }, "wrong digest": func(v *LaunchSpec) { v.BinarySHA256 = strings.Repeat("0", 64) },
		"root UID": func(v *LaunchSpec) { v.UID = 0 }, "root GID": func(v *LaunchSpec) { v.GID = 0 }, "operator UID": func(v *LaunchSpec) { v.UID = v.OperatorUID },
		"missing KVM": func(v *LaunchSpec) { v.SupplementaryGIDs = nil }, "extra group": func(v *LaunchSpec) { v.SupplementaryGIDs = append(v.SupplementaryGIDs, 994) }, "wrong KVM": func(v *LaunchSpec) { v.SupplementaryGIDs[0]++ },
		"relative executable": func(v *LaunchSpec) { v.BinaryPath = "cloud-hypervisor" }, "relative runtime": func(v *LaunchSpec) { v.WorkingDirectory = "runtime" },
		"socket escape": func(v *LaunchSpec) { v.APISocket = "/run/ehjint/api.sock" }, "nested socket": func(v *LaunchSpec) { v.APISocket = filepath.Join(v.WorkingDirectory, "nested", "api.sock") },
		"duplicate": func(v *LaunchSpec) { v.EventMonitor = v.APISocket }, "noncanonical": func(v *LaunchSpec) { v.WorkingDirectory += "/../test-machine" },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			v := cloneLaunchSpec(base)
			mutate(&v)
			if err := v.Validate(); err == nil {
				t.Fatal("invalid launch spec accepted")
			}
		})
	}
}

func TestLaunchSpecUsesImmutableSealedMemfd(t *testing.T) {
	base := baseLaunchSpec()
	file, err := newSealedLaunchSpec(base)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	seals, err := unix.FcntlInt(file.Fd(), unix.F_GET_SEALS, 0)
	if err != nil {
		t.Fatal(err)
	}
	if seals&launchSpecSeals != launchSpecSeals {
		t.Fatalf("seals=%#x", seals)
	}
	if _, err := file.Write([]byte("mutation")); err == nil {
		t.Fatal("sealed launch spec remained writable")
	}
	fd, err := unix.Dup(int(file.Fd()))
	if err != nil {
		t.Fatal(err)
	}
	observed, err := readSealedLaunchSpec(fd)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(observed, base) {
		t.Fatalf("observed=%#v want=%#v", observed, base)
	}
}

func TestLaunchSpecRejectsUnsealedMalformedOversizedAndInvalidDescriptors(t *testing.T) {
	if _, err := readSealedLaunchSpec(2); err == nil {
		t.Fatal("invalid descriptor accepted")
	}
	fd, err := unix.MemfdCreate("unsealed-vmm-spec", unix.MFD_CLOEXEC|unix.MFD_ALLOW_SEALING)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(fd)
	if _, err := unix.Write(fd, []byte(`{}`)); err != nil {
		t.Fatal(err)
	}
	if _, err := readSealedLaunchSpec(fd); err == nil || !strings.Contains(err.Error(), "not immutable") {
		t.Fatalf("unsealed error=%v", err)
	}
	for name, content := range map[string][]byte{"malformed": []byte(`{"schema_version":`), "oversized": make([]byte, maxLaunchSpec+1)} {
		t.Run(name, func(t *testing.T) {
			bad, err := unix.MemfdCreate("bad-vmm-spec", unix.MFD_CLOEXEC|unix.MFD_ALLOW_SEALING)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := unix.Write(bad, content); err != nil {
				_ = unix.Close(bad)
				t.Fatal(err)
			}
			if _, err := unix.FcntlInt(uintptr(bad), unix.F_ADD_SEALS, launchSpecSeals); err != nil {
				_ = unix.Close(bad)
				t.Fatal(err)
			}
			if _, err := readSealedLaunchSpec(bad); err == nil {
				t.Fatal("invalid sealed launch spec accepted")
			}
		})
	}
}

func TestExecutableVerificationRejectsDigestSymlinkAndNonRegularFiles(t *testing.T) {
	path := "/usr/bin/true"
	digest, err := hashPath(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := verifyExecutable(path, digest); err != nil {
		t.Fatalf("safe executable rejected: %v", err)
	}
	if err := verifyExecutable(path, strings.Repeat("0", 64)); err == nil {
		t.Fatal("wrong digest accepted")
	}
	link := filepath.Join(t.TempDir(), "true")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	if err := verifyExecutable(link, digest); err == nil {
		t.Fatal("symlink accepted")
	}
	if err := verifyExecutable(t.TempDir(), digest); err == nil {
		t.Fatal("directory accepted")
	}
}

func TestParseSpecFD(t *testing.T) {
	if v, err := ParseSpecFD("3"); err != nil || v != 3 {
		t.Fatalf("ParseSpecFD=%d,%v", v, err)
	}
	for _, v := range []string{"", "2", "1025", "shell", "3;id"} {
		if _, err := ParseSpecFD(v); err == nil {
			t.Fatalf("invalid descriptor %q accepted", v)
		}
	}
}

func TestProcessStatAndStatusParsing(t *testing.T) {
	stat := "123 (cloud hypervisor) S 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 424242 20"
	state, start, err := parseProcessStat(stat)
	if err != nil || state != "S" || start != 424242 {
		t.Fatalf("parseProcessStat=%q,%d,%v", state, start, err)
	}
	status := strings.NewReader("Uid:\t62001\t62001\t62001\t62001\nGid:\t62002\t62002\t62002\t62002\nGroups:\t993\nNoNewPrivs:\t1\nSeccomp:\t2\nSeccomp_filters:\t1\nCapInh:\t0000000000000000\nCapPrm:\t0000000000000000\nCapEff:\t0000000000000000\nCapBnd:\t0000000000000000\nCapAmb:\t0000000000000000\n")
	fields, err := parseStatus(status)
	if err != nil {
		t.Fatal(err)
	}
	if fields.uids[0] != 62001 || fields.gids[0] != 62002 || !fields.noNewPrivs || fields.seccomp != 2 || fields.seccompFilters != 1 || !reflect.DeepEqual(fields.groups, []uint32{993}) {
		t.Fatalf("fields=%#v", fields)
	}
	if _, err := parseStatus(strings.NewReader("Uid:\t1\t1\t1\t1\n")); err == nil {
		t.Fatal("truncated status accepted")
	}
}

func baseProcessIdentity() ProcessIdentity {
	return ProcessIdentity{PID: 4242, StartTime: 123456, State: "S", ExecutablePath: "/opt/ehjint/lib/cloud-hypervisor-v53.0", ExecutableSHA256: chapi.BinarySHA256, RealUID: 62001, EffectiveUID: 62001, SavedUID: 62001, FilesystemUID: 62001, UID: 62001, RealGID: 62002, EffectiveGID: 62002, SavedGID: 62002, FilesystemGID: 62002, GID: 62002, SupplementaryGIDs: []uint32{993}, NoNewPrivs: true, SeccompMode: 0, SeccompFilters: 0, PIDFD: 9}
}
func cloneProcessIdentity(v ProcessIdentity) ProcessIdentity {
	v.SupplementaryGIDs = append([]uint32(nil), v.SupplementaryGIDs...)
	return v
}

func TestProcessIdentityRejectsPIDReusePrivilegeAndCapabilityDrift(t *testing.T) {
	base := baseProcessIdentity()
	if err := base.Validate(base.ExecutablePath, base.ExecutableSHA256, base.UID, base.GID, base.SupplementaryGIDs); err != nil {
		t.Fatalf("valid identity rejected: %v", err)
	}
	cases := map[string]func(*ProcessIdentity){
		"PID": func(v *ProcessIdentity) { v.PID = 0 }, "start": func(v *ProcessIdentity) { v.StartTime = 0 }, "dead": func(v *ProcessIdentity) { v.State = "Z" }, "pidfd": func(v *ProcessIdentity) { v.PIDFD = -1 },
		"executable": func(v *ProcessIdentity) { v.ExecutablePath += ".wrong" }, "digest": func(v *ProcessIdentity) { v.ExecutableSHA256 = strings.Repeat("0", 64) },
		"root UID": func(v *ProcessIdentity) { v.RealUID = 0 }, "effective UID": func(v *ProcessIdentity) { v.EffectiveUID++ }, "saved UID": func(v *ProcessIdentity) { v.SavedUID++ }, "fs UID": func(v *ProcessIdentity) { v.FilesystemUID++ },
		"real GID": func(v *ProcessIdentity) { v.RealGID++ }, "effective GID": func(v *ProcessIdentity) { v.EffectiveGID++ }, "saved GID": func(v *ProcessIdentity) { v.SavedGID++ }, "fs GID": func(v *ProcessIdentity) { v.FilesystemGID++ },
		"missing KVM": func(v *ProcessIdentity) { v.SupplementaryGIDs = nil }, "extra group": func(v *ProcessIdentity) { v.SupplementaryGIDs = append(v.SupplementaryGIDs, 994) }, "NNP": func(v *ProcessIdentity) { v.NoNewPrivs = false },
		"CapInh": func(v *ProcessIdentity) { v.CapInheritable = 1 }, "CapPrm": func(v *ProcessIdentity) { v.CapPermitted = 1 }, "CapEff": func(v *ProcessIdentity) { v.CapEffective = 1 }, "CapBnd": func(v *ProcessIdentity) { v.CapBounding = 1 }, "CapAmb": func(v *ProcessIdentity) { v.CapAmbient = 1 },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			v := cloneProcessIdentity(base)
			mutate(&v)
			if err := v.Validate(base.ExecutablePath, base.ExecutableSHA256, base.UID, base.GID, base.SupplementaryGIDs); err == nil {
				t.Fatal("unsafe identity accepted")
			}
		})
	}
}

func TestDurableProcessIdentityRejectsEveryObservedConflict(t *testing.T) {
	expected := baseProcessIdentity()
	cases := map[string]func(*ProcessIdentity){"PID reuse": func(v *ProcessIdentity) { v.PID++ }, "start": func(v *ProcessIdentity) { v.StartTime++ }, "executable": func(v *ProcessIdentity) { v.ExecutablePath += ".wrong" }, "digest": func(v *ProcessIdentity) { v.ExecutableSHA256 = strings.Repeat("1", 64) }, "UID": func(v *ProcessIdentity) { v.EffectiveUID++ }, "GID": func(v *ProcessIdentity) { v.EffectiveGID++ }, "extra group": func(v *ProcessIdentity) { v.SupplementaryGIDs = append(v.SupplementaryGIDs, 994) }, "NNP": func(v *ProcessIdentity) { v.NoNewPrivs = false }, "cap": func(v *ProcessIdentity) { v.CapBounding = 1 }, "seccomp": func(v *ProcessIdentity) { v.SeccompMode = 1 }, "dead": func(v *ProcessIdentity) { v.State = "Z" }}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			v := cloneProcessIdentity(expected)
			mutate(&v)
			if err := v.MatchesDurable(expected); err == nil {
				t.Fatal("durable conflict accepted")
			}
		})
	}
}

func baseVMMIdentity() VMMIdentity {
	p := baseProcessIdentity()
	return VMMIdentity{Process: p, APISocket: SocketIdentity{Path: "/run/ehjint/machines/test-machine/api.sock", UID: p.UID, GID: p.GID, Mode: 0o700}, APIPID: int64(p.PID), BuildVersion: chapi.ReleaseVersion, RuntimeAPIVersion: chapi.RuntimeAPIVersion, Features: []string{"kvm"}}
}
func cloneVMMIdentity(v VMMIdentity) VMMIdentity {
	v.Process = cloneProcessIdentity(v.Process)
	v.Features = append([]string(nil), v.Features...)
	return v
}

func TestDurableVMMIdentityRejectsAPIAndSocketConflicts(t *testing.T) {
	expected := baseVMMIdentity()
	cases := map[string]func(*VMMIdentity){
		"API PID": func(v *VMMIdentity) { v.APIPID++ }, "build": func(v *VMMIdentity) { v.BuildVersion = "v54.0" }, "runtime": func(v *VMMIdentity) { v.RuntimeAPIVersion = "54.0.0" },
		"socket path": func(v *VMMIdentity) { v.APISocket.Path += ".wrong" }, "socket UID": func(v *VMMIdentity) { v.APISocket.UID++ }, "socket GID": func(v *VMMIdentity) { v.APISocket.GID++ }, "socket mode": func(v *VMMIdentity) { v.APISocket.Mode = 0o770 }, "features": func(v *VMMIdentity) { v.Features = []string{"mshv"} },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			v := cloneVMMIdentity(expected)
			mutate(&v)
			if err := v.matchesDurable(expected); err == nil {
				t.Fatal("durable VMM conflict accepted")
			}
		})
	}
}

func TestStartAndAdoptSpecificationsArePinnedAndNarrow(t *testing.T) {
	paths := DefaultPaths("/run/ehjint/machines/test-machine")
	start := StartSpec{HelperPath: "/opt/ehjint/bin/ehjint", HelperSHA256: strings.Repeat("a", 64), BinaryPath: "/opt/ehjint/lib/cloud-hypervisor-v53.0", BinarySHA256: chapi.BinarySHA256, UID: 62001, GID: 62002, OperatorUID: 1000, KVMGID: 993, SupplementaryGIDs: []uint32{993}, Paths: paths}
	if err := start.Validate(); err != nil {
		t.Fatalf("valid start spec rejected: %v", err)
	}
	startCases := map[string]func(*StartSpec){"helper digest": func(v *StartSpec) { v.HelperSHA256 = "bad" }, "binary digest": func(v *StartSpec) { v.BinarySHA256 = strings.Repeat("0", 64) }, "root UID": func(v *StartSpec) { v.UID = 0 }, "operator UID": func(v *StartSpec) { v.UID = v.OperatorUID }, "extra group": func(v *StartSpec) { v.SupplementaryGIDs = append(v.SupplementaryGIDs, 994) }, "path escape": func(v *StartSpec) { v.Paths.APISocket = "/tmp/api.sock" }}
	for name, mutate := range startCases {
		t.Run("start "+name, func(t *testing.T) {
			v := start
			v.SupplementaryGIDs = append([]uint32(nil), start.SupplementaryGIDs...)
			mutate(&v)
			if err := v.Validate(); err == nil {
				t.Fatal("invalid start spec accepted")
			}
		})
	}

	identity := baseVMMIdentity()
	identity.APISocket.Path = paths.APISocket
	adopt := AdoptSpec{Identity: identity, Paths: paths, APITimeout: time.Second}
	if err := adopt.Validate(); err != nil {
		t.Fatalf("valid adoption spec rejected: %v", err)
	}
	adoptCases := map[string]func(*AdoptSpec){
		"root": func(v *AdoptSpec) { v.Identity.Process.UID = 0 }, "API PID": func(v *AdoptSpec) { v.Identity.APIPID++ }, "build": func(v *AdoptSpec) { v.Identity.BuildVersion = "v54.0" }, "runtime": func(v *AdoptSpec) { v.Identity.RuntimeAPIVersion = "54.0.0" },
		"digest": func(v *AdoptSpec) { v.Identity.Process.ExecutableSHA256 = strings.Repeat("0", 64) }, "socket escape": func(v *AdoptSpec) { v.Identity.APISocket.Path = "/tmp/api.sock" }, "socket owner": func(v *AdoptSpec) { v.Identity.APISocket.UID++ }, "socket mode": func(v *AdoptSpec) { v.Identity.APISocket.Mode = 0o777 }, "missing group": func(v *AdoptSpec) { v.Identity.Process.SupplementaryGIDs = nil },
	}
	for name, mutate := range adoptCases {
		t.Run("adopt "+name, func(t *testing.T) {
			v := adopt
			v.Identity = cloneVMMIdentity(adopt.Identity)
			mutate(&v)
			if err := v.Validate(); err == nil {
				t.Fatal("invalid adoption spec accepted")
			}
		})
	}
}

func TestInspectProcessAndPIDFDObservation(t *testing.T) {
	identity, err := InspectProcess(os.Getpid())
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(identity.PIDFD)
	if identity.PID != os.Getpid() || identity.StartTime == 0 || identity.ExecutablePath == "" || len(identity.ExecutableSHA256) != 64 || identity.PIDFD < 0 {
		t.Fatalf("identity=%+v", identity)
	}
}

func TestWaitPIDFDObservesExactChildExitAndTimeout(t *testing.T) {
	cmd := exec.Command("/usr/bin/sleep", "0.05")
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	fd, err := unix.PidfdOpen(cmd.Process.Pid, 0)
	if err != nil {
		_ = cmd.Process.Kill()
		_, _ = cmd.Process.Wait()
		t.Fatal(err)
	}
	defer unix.Close(fd)
	wait := make(chan error, 1)
	go func() { wait <- cmd.Wait() }()
	if err := waitPIDFD(context.Background(), fd, time.Second, wait); err != nil {
		t.Fatal(err)
	}
	long := exec.Command("/usr/bin/sleep", "10")
	if err := long.Start(); err != nil {
		t.Fatal(err)
	}
	longFD, err := unix.PidfdOpen(long.Process.Pid, 0)
	if err != nil {
		_ = long.Process.Kill()
		_, _ = long.Process.Wait()
		t.Fatal(err)
	}
	defer unix.Close(longFD)
	if err := waitPIDFD(context.Background(), longFD, 20*time.Millisecond, nil); err == nil || !strings.Contains(err.Error(), "timed out") {
		t.Fatalf("timeout error=%v", err)
	}
	_ = long.Process.Kill()
	_, _ = long.Process.Wait()
}

func TestIdentityJSONExcludesPIDFD(t *testing.T) {
	encoded, err := json.Marshal(baseVMMIdentity())
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), "pidfd") {
		t.Fatalf("durable identity leaked pidfd: %s", encoded)
	}
}

func TestCleanupRuntimeRemovesOnlyExactOwnedObjects(t *testing.T) {
	requireRootRuntimeTests(t)
	paths := makeRuntime(t)
	uid, gid := uint32(os.Geteuid()), uint32(os.Getegid())
	createRuntimeObjects(t, paths, uid, gid)
	if err := CleanupRuntime(paths, uid, gid); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(paths.RuntimeDir); !os.IsNotExist(err) {
		t.Fatalf("runtime remains: %v", err)
	}
}

func TestCleanupRuntimeRefusesAmbiguityAndLiveOwnership(t *testing.T) {
	requireRootRuntimeTests(t)
	uid, gid := uint32(os.Geteuid()), uint32(os.Getegid())
	t.Run("unknown", func(t *testing.T) {
		paths := makeRuntime(t)
		unknown := filepath.Join(paths.RuntimeDir, "unknown")
		if err := os.WriteFile(unknown, []byte("undeclared"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := CleanupRuntime(paths, uid, gid); err == nil || !strings.Contains(err.Error(), "nonempty") {
			t.Fatalf("cleanup error=%v", err)
		}
		if _, err := os.Lstat(unknown); err != nil {
			t.Fatalf("unknown object removed: %v", err)
		}
		_ = os.Remove(unknown)
		_ = os.Remove(paths.RuntimeDir)
	})
	t.Run("wrong mode", func(t *testing.T) {
		paths := makeRuntime(t)
		if err := os.WriteFile(paths.StdoutFile, []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := CleanupRuntime(paths, uid, gid); err == nil || !strings.Contains(err.Error(), "invalid type or mode") {
			t.Fatalf("cleanup error=%v", err)
		}
		_ = os.Remove(paths.StdoutFile)
		_ = os.Remove(paths.RuntimeDir)
	})
	t.Run("symlink", func(t *testing.T) {
		paths := makeRuntime(t)
		if err := os.Symlink("/etc/passwd", paths.LockFile); err != nil {
			t.Fatal(err)
		}
		if err := CleanupRuntime(paths, uid, gid); err == nil || !strings.Contains(err.Error(), "symlink") {
			t.Fatalf("cleanup error=%v", err)
		}
		_ = os.Remove(paths.LockFile)
		_ = os.Remove(paths.RuntimeDir)
	})
	t.Run("live cwd", func(t *testing.T) {
		paths := makeRuntime(t)
		cmd := exec.Command("/bin/sh", "-c", "cd -- \"$1\" && exec /usr/bin/sleep 10", "sh", paths.RuntimeDir)
		if err := cmd.Start(); err != nil {
			t.Fatal(err)
		}
		defer func() { _ = cmd.Process.Kill(); _, _ = cmd.Process.Wait() }()
		deadline := time.Now().Add(time.Second)
		for time.Now().Before(deadline) {
			cwd, _ := os.Readlink(fmt.Sprintf("/proc/%d/cwd", cmd.Process.Pid))
			if cwd == paths.RuntimeDir {
				break
			}
			time.Sleep(10 * time.Millisecond)
		}
		if err := CleanupRuntime(paths, uid, gid); err == nil || !strings.Contains(err.Error(), "still owns") {
			t.Fatalf("cleanup error=%v", err)
		}
		_ = cmd.Process.Kill()
		_, _ = cmd.Process.Wait()
		if err := CleanupRuntime(paths, uid, gid); err != nil {
			t.Fatal(err)
		}
	})
}

func requireRootRuntimeTests(t *testing.T) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("exact /run/ehjint ownership tests require root")
	}
	if err := os.MkdirAll("/run/ehjint", 0o750); err != nil {
		t.Skipf("cannot prepare /run/ehjint: %v", err)
	}
	info, err := os.Lstat("/run/ehjint")
	if err != nil {
		t.Fatal(err)
	}
	stat := info.Sys().(*syscall.Stat_t)
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o022 != 0 || stat.Uid != 0 {
		t.Fatal("/run/ehjint is not secure root-owned directory")
	}
}

func makeRuntime(t *testing.T) Paths {
	t.Helper()
	dir, err := os.MkdirTemp("/run/ehjint", "vmm-unit-")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return DefaultPaths(dir)
}

func createRuntimeObjects(t *testing.T, paths Paths, uid, gid uint32) {
	t.Helper()
	for _, path := range []string{paths.APILock, paths.EventMonitor, paths.LogFile, paths.StdoutFile, paths.StderrFile, paths.LockFile} {
		if err := os.WriteFile(path, []byte("owned"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chown(path, int(uid), int(gid)); err != nil {
			t.Fatal(err)
		}
	}
	for _, path := range []string{paths.APISocket, paths.VsockSocket} {
		listener, err := net.Listen("unix", path)
		if err != nil {
			t.Fatal(err)
		}
		listener.(*net.UnixListener).SetUnlinkOnClose(false)
		if err := os.Chmod(path, 0o700); err != nil {
			_ = listener.Close()
			t.Fatal(err)
		}
		if err := os.Chown(path, int(uid), int(gid)); err != nil {
			_ = listener.Close()
			t.Fatal(err)
		}
		if err := listener.Close(); err != nil {
			t.Fatal(err)
		}
	}
}
