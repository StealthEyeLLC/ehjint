package state

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/StealthEyeLLC/ehjint/internal/contracts"
)

func openTestStore(t *testing.T) (*Store, string) {
	t.Helper()
	root := t.TempDir()
	path := filepath.Join(root, "controller.sqlite3")
	store, err := Open(context.Background(), path)
	if err != nil {
		t.Fatalf("open state store: %v", err)
	}
	t.Cleanup(func() {
		if err := store.Close(); err != nil {
			t.Errorf("close state store: %v", err)
		}
	})
	return store, path
}

func testMachineSpec(root string) MachineSpec {
	return MachineSpec{
		MachineID:        "machine-0001",
		StableName:       "alpha",
		ManifestPath:     filepath.Join(root, "machines", "machine-0001", "manifest.json"),
		ManifestDigest:   strings.Repeat("a", 64),
		CreatingRelease:  "release-0001",
		VMMVersion:       "53.0",
		VMMDigest:        strings.Repeat("b", 64),
		GuestImageDigest: strings.Repeat("c", 64),
		FirmwareDigest:   strings.Repeat("d", 64),
		OverlayIdentity:  "dev:ino:1:2",
		VsockCID:         9001,
		AgentPort:        17777,
		VMMIdentity:      "ehjint-vmm-machine-0001",
		VMMUID:           42001,
		VMMGID:           42001,
		APISocket:        filepath.Join(root, "run", "machine-0001", "cloud-hypervisor.sock"),
		VsockSocket:      filepath.Join(root, "run", "machine-0001", "vsock.sock"),
	}
}

func TestOpenPragmasMigrationAndReopen(t *testing.T) {
	store, path := openTestStore(t)
	ctx := context.Background()
	version, err := store.Schema(ctx)
	if err != nil || version != SchemaVersion {
		t.Fatalf("schema version = %d, %v", version, err)
	}
	pragmas, err := store.VerifyPragmas(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if pragmas.JournalMode != "wal" || !pragmas.ForeignKeys || pragmas.Synchronous != 2 || pragmas.BusyTimeout != 5000 {
		t.Fatalf("unexpected pragmas: %+v", pragmas)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("database mode = %04o", info.Mode().Perm())
	}
	if err := store.RecordCompatibility(ctx, "machine_manifest", 1, strings.Repeat("e", 64)); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	version, digest, err := reopened.Compatibility(ctx, "machine_manifest")
	if err != nil || version != 1 || digest != strings.Repeat("e", 64) {
		t.Fatalf("compatibility after reopen = %d %q %v", version, digest, err)
	}
}

func TestOpenRejectsUnsafeAndCorruptDatabasePaths(t *testing.T) {
	ctx := context.Background()
	if _, err := Open(ctx, "relative.sqlite3"); err == nil {
		t.Fatal("relative database path accepted")
	}
	root := t.TempDir()
	world := filepath.Join(root, "world")
	if err := os.Mkdir(world, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(world, 0o777); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(ctx, filepath.Join(world, "controller.sqlite3")); err == nil {
		t.Fatal("world-writable database parent accepted")
	}
	target := filepath.Join(root, "target.sqlite3")
	if err := os.WriteFile(target, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "link.sqlite3")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(ctx, link); err == nil {
		t.Fatal("database symlink accepted")
	}
	corrupt := filepath.Join(root, "corrupt.sqlite3")
	if err := os.WriteFile(corrupt, []byte("not a sqlite database"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(ctx, corrupt); err == nil {
		t.Fatal("corrupt database accepted")
	}
}

func TestOperationIdempotencyTransitionsCancellationAndRecovery(t *testing.T) {
	store, path := openTestStore(t)
	ctx := context.Background()
	request := OperationRequest{
		OperationID:      "operation-0001",
		OperationName:    "machine.create",
		OperationVersion: 1,
		IdempotencyKey:   "create-alpha",
		RequestDigest:    strings.Repeat("1", 64),
		MachineID:        "machine-0001",
	}
	created, replay, err := store.CreateOperation(ctx, request)
	if err != nil || replay || created.State != string(contracts.StateAccepted) {
		t.Fatalf("create operation = %+v replay=%v err=%v", created, replay, err)
	}
	replayRequest := request
	replayRequest.OperationID = "operation-unused-replay-id"
	replayed, replay, err := store.CreateOperation(ctx, replayRequest)
	if err != nil || !replay || replayed.OperationID != created.OperationID {
		t.Fatalf("exact replay = %+v replay=%v err=%v", replayed, replay, err)
	}
	conflict := request
	conflict.OperationID = "operation-conflict"
	conflict.RequestDigest = strings.Repeat("2", 64)
	if _, _, err := store.CreateOperation(ctx, conflict); !errors.Is(err, ErrIdempotencyConflict) {
		t.Fatalf("conflicting replay error = %v", err)
	}
	if _, err := store.SetOperationPaths(ctx, created.OperationID, "/var/lib/ehjint/operations/operation-0001/result.json", "/var/lib/ehjint/operations/operation-0001/stdout", "/var/lib/ehjint/operations/operation-0001/stderr"); err != nil {
		t.Fatal(err)
	}
	if _, err := store.AdvanceStreamCursors(ctx, created.OperationID, 11, 7); err != nil {
		t.Fatal(err)
	}
	operation, err := store.AdvanceStreamCursors(ctx, created.OperationID, 3, 2)
	if err != nil || operation.StdoutCursor != 11 || operation.StderrCursor != 7 {
		t.Fatalf("monotonic cursors = %+v %v", operation, err)
	}
	operation, err = store.TransitionOperation(ctx, created.OperationID, contracts.StateRunning, OperationUpdate{})
	if err != nil || operation.StartedAt == nil || operation.FinishedAt != nil {
		t.Fatalf("running transition = %+v %v", operation, err)
	}
	operation, err = store.RequestCancellation(ctx, created.OperationID)
	if err != nil || !operation.CancellationRequested {
		t.Fatalf("cancellation intent = %+v %v", operation, err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	operation, err = reopened.GetOperation(ctx, created.OperationID)
	if err != nil || operation.State != string(contracts.StateRunning) || !operation.CancellationRequested || operation.StdoutCursor != 11 {
		t.Fatalf("recovered operation = %+v %v", operation, err)
	}
	operation, err = reopened.TransitionOperation(ctx, created.OperationID, contracts.StateCancelled, OperationUpdate{ErrorCode: "cancelled", ErrorMessage: "operator requested cancellation"})
	if err != nil || operation.FinishedAt == nil || operation.State != string(contracts.StateCancelled) {
		t.Fatalf("cancel transition = %+v %v", operation, err)
	}
	if _, err := reopened.TransitionOperation(ctx, created.OperationID, contracts.StateRunning, OperationUpdate{}); !errors.Is(err, ErrTerminalOperation) {
		t.Fatalf("terminal operation reopened: %v", err)
	}
	terminal, err := reopened.TransitionOperation(ctx, created.OperationID, contracts.StateCancelled, OperationUpdate{ErrorMessage: "attempted rewrite"})
	if err != nil || terminal.ErrorMessage != "operator requested cancellation" {
		t.Fatalf("idempotent terminal transition rewrote truth: %+v %v", terminal, err)
	}
}

func TestConcurrentIdempotencyHasOneDurableAuthority(t *testing.T) {
	store, _ := openTestStore(t)
	ctx := context.Background()
	const callers = 16
	var createdCount atomic.Int64
	var replayCount atomic.Int64
	var failures atomic.Int64
	var wait sync.WaitGroup
	wait.Add(callers)
	for index := 0; index < callers; index++ {
		index := index
		go func() {
			defer wait.Done()
			operation, replay, err := store.CreateOperation(ctx, OperationRequest{
				OperationID:      "operation-concurrent-" + string(rune('a'+index)),
				OperationName:    "machine.start",
				OperationVersion: 1,
				IdempotencyKey:   "start-alpha-once",
				RequestDigest:    strings.Repeat("3", 64),
				MachineID:        "machine-0001",
			})
			if err != nil || operation.IdempotencyKey != "start-alpha-once" {
				failures.Add(1)
				return
			}
			if replay {
				replayCount.Add(1)
			} else {
				createdCount.Add(1)
			}
		}()
	}
	wait.Wait()
	if failures.Load() != 0 || createdCount.Load() != 1 || replayCount.Load() != callers-1 {
		t.Fatalf("created=%d replay=%d failures=%d", createdCount.Load(), replayCount.Load(), failures.Load())
	}
	operations, err := store.ListNonterminalOperations(ctx)
	if err != nil || len(operations) != 1 {
		t.Fatalf("nonterminal authority = %+v %v", operations, err)
	}
}

func TestMachineLifecycleOwnershipAndRecovery(t *testing.T) {
	store, path := openTestStore(t)
	ctx := context.Background()
	spec := testMachineSpec(filepath.Dir(path))
	machine, replay, err := store.EnsureMachine(ctx, spec)
	if err != nil || replay || machine.ObservedState != ObservedAbsent || machine.DesiredState != DesiredStopped {
		t.Fatalf("ensure machine = %+v replay=%v err=%v", machine, replay, err)
	}
	machine, replay, err = store.EnsureMachine(ctx, spec)
	if err != nil || !replay {
		t.Fatalf("machine replay = %+v replay=%v err=%v", machine, replay, err)
	}
	changed := spec
	changed.OverlayIdentity = "dev:ino:other"
	if _, _, err := store.EnsureMachine(ctx, changed); !errors.Is(err, ErrMachineConflict) {
		t.Fatalf("machine conflict error = %v", err)
	}
	if _, err := store.SetMachineDesired(ctx, spec.MachineID, DesiredRunning); err != nil {
		t.Fatal(err)
	}
	for _, next := range []ObservedState{ObservedPreparing, ObservedStarting, ObservedRunning} {
		machine, err = store.TransitionMachineObserved(ctx, spec.MachineID, next, "")
		if err != nil || machine.ObservedState != next {
			t.Fatalf("transition to %s = %+v %v", next, machine, err)
		}
	}
	if _, err := store.TransitionMachineObserved(ctx, spec.MachineID, ObservedAbsent, ""); err == nil {
		t.Fatal("undeclared running-to-absent transition accepted")
	}
	machine, err = store.UpdateRuntimeObservation(ctx, spec.MachineID, RuntimeObservation{
		VMMPID:               1234,
		ProcessStartIdentity: "proc-start-88",
		GuestBootID:          "guest-boot-1",
		ReadinessState:       "ready",
	})
	if err != nil || machine.VMMPID != 1234 || machine.GuestBootID != "guest-boot-1" {
		t.Fatalf("runtime observation = %+v %v", machine, err)
	}
	uid, gid := spec.VMMUID, spec.VMMGID
	resource, replay, err := store.RecordResource(ctx, OwnedResource{
		MachineID: spec.MachineID, Kind: "overlay", Path: spec.ManifestPath + ".overlay",
		Identity: spec.OverlayIdentity, Digest: strings.Repeat("f", 64), UID: &uid, GID: &gid,
	})
	if err != nil || replay || resource.ResourceID == 0 {
		t.Fatalf("record resource = %+v replay=%v err=%v", resource, replay, err)
	}
	_, replay, err = store.RecordResource(ctx, OwnedResource{
		MachineID: spec.MachineID, Kind: "overlay", Path: spec.ManifestPath + ".overlay",
		Identity: spec.OverlayIdentity, Digest: strings.Repeat("f", 64), UID: &uid, GID: &gid,
	})
	if err != nil || !replay {
		t.Fatalf("resource replay=%v err=%v", replay, err)
	}
	if _, _, err := store.RecordResource(ctx, OwnedResource{MachineID: "missing-machine", Kind: "file", Path: "/tmp/missing"}); err == nil {
		t.Fatal("resource for unknown machine accepted")
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	machine, err = reopened.GetMachine(ctx, spec.StableName)
	if err != nil || machine.ObservedState != ObservedRunning || machine.ReadinessState != "ready" {
		t.Fatalf("recovered machine = %+v %v", machine, err)
	}
	if _, err := reopened.SetMachineDesired(ctx, spec.MachineID, DesiredAbsent); err != nil {
		t.Fatal(err)
	}
	if _, err := reopened.TransitionMachineObserved(ctx, spec.MachineID, ObservedRemoving, ""); err != nil {
		t.Fatal(err)
	}
	if _, err := reopened.TransitionMachineObserved(ctx, spec.MachineID, ObservedAbsent, ""); err != nil {
		t.Fatal(err)
	}
	if err := reopened.DeleteMachineProjection(ctx, spec.MachineID); err == nil {
		t.Fatal("machine projection deleted while owned resource remained")
	}
	resources, err := reopened.ListResources(ctx, spec.MachineID)
	if err != nil || len(resources) != 1 {
		t.Fatalf("owned resources = %+v %v", resources, err)
	}
	if err := reopened.ForgetResource(ctx, resources[0].ResourceID); err != nil {
		t.Fatal(err)
	}
	if err := reopened.DeleteMachineProjection(ctx, spec.MachineID); err != nil {
		t.Fatal(err)
	}
	if _, err := reopened.GetMachine(ctx, spec.MachineID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("deleted machine lookup = %v", err)
	}
}

func TestObservedTransitionMatrixRejectsUnknowns(t *testing.T) {
	if err := ValidateObservedTransition(ObservedAbsent, ObservedRunning); err == nil {
		t.Fatal("absent-to-running accepted")
	}
	if err := ValidateObservedTransition(ObservedState("invented"), ObservedAbsent); err == nil {
		t.Fatal("unknown source accepted")
	}
}

func TestMachineAuthorityAllocationTransitionAndCollisions(t *testing.T) {
	store, path := openTestStore(t)
	defer store.Close()
	ctx := context.Background()
	spec := testMachineSpec(filepath.Dir(path))
	authority := testMachineAuthority(spec, filepath.Dir(path))

	machine, allocated, replay, err := store.AllocateMachine(ctx, spec, authority)
	if err != nil || replay || machine.MachineID != spec.MachineID || allocated.HostUsername != authority.HostUsername {
		t.Fatalf("allocate machine = %+v %+v replay=%v err=%v", machine, allocated, replay, err)
	}
	machine, allocated, replay, err = store.AllocateMachine(ctx, spec, authority)
	if err != nil || !replay || allocated.RuntimeDirectory != authority.RuntimeDirectory {
		t.Fatalf("replay allocation = %+v %+v replay=%v err=%v", machine, allocated, replay, err)
	}

	conflictSpec := spec
	conflictSpec.MachineID = "mach_aaaaaaaaaaaaaaaaaaaaaaaaaa"
	conflictSpec.StableName = "other-machine"
	conflictSpec.ManifestPath = filepath.Join(filepath.Dir(path), "other", "manifest.json")
	conflictSpec.APISocket = filepath.Join(filepath.Dir(path), "other", "api.sock")
	conflictSpec.VsockSocket = filepath.Join(filepath.Dir(path), "other", "vsock.sock")
	conflictSpec.VMMIdentity = "ehjint-vmm-other"
	conflictSpec.VMMUID++
	conflictSpec.VMMGID++
	conflictSpec.VsockCID++
	conflict := authority
	conflict.MachineID = conflictSpec.MachineID
	conflict.CreationOperationID = "op_aaaaaaaaaaaaaaaaaaaaaaaaaa"
	conflict.HostUsername = "ehjintm-other"
	conflict.HostGroupname = "ehjintm-other"
	conflict.StateDirectory = filepath.Join(filepath.Dir(path), "other")
	conflict.RuntimeDirectory = filepath.Join(filepath.Dir(path), "runtime-other")
	conflict.OverlayPath = filepath.Join(conflict.StateDirectory, "root.qcow2")
	conflict.SeedPath = filepath.Join(conflict.StateDirectory, "cidata.img")
	conflict.PKIDirectory = filepath.Join(conflict.StateDirectory, "pki")
	conflict.CACertificatePath = filepath.Join(conflict.PKIDirectory, "ca.crt")
	conflict.CAPrivateKeyPath = filepath.Join(conflict.PKIDirectory, "ca.key")
	conflict.ControllerCertificatePath = filepath.Join(conflict.PKIDirectory, "controller.crt")
	conflict.ControllerPrivateKeyPath = filepath.Join(conflict.PKIDirectory, "controller.key")
	conflict.GuestCertificatePath = filepath.Join(conflict.PKIDirectory, "guest.crt")
	conflict.GuestPrivateKeyPath = filepath.Join(conflict.PKIDirectory, "guest.key")
	conflict.VMMIdentityPath = filepath.Join(conflict.StateDirectory, "vmm-identity.json")
	conflict.OverlayPath = authority.OverlayPath
	if _, _, _, err := store.AllocateMachine(ctx, conflictSpec, conflict); !errors.Is(err, ErrMachineConflict) {
		t.Fatalf("overlay collision error = %v", err)
	}

	opID := "op_baaaaaaaaaaaaaaaaaaaaaaaaa"
	machine, transition, err := store.TransitionMachineLifecycle(ctx, spec.MachineID, ObservedPreparing, opID, "prepare-key", `{"overlay":true}`, `{"overlay":false}`, "", "", "continue")
	if err != nil || machine.ObservedState != ObservedPreparing || transition.PreviousState != ObservedAbsent || transition.RequestedState != ObservedPreparing {
		t.Fatalf("transition = %+v %+v err=%v", machine, transition, err)
	}
	transitions, err := store.ListMachineTransitions(ctx, spec.MachineID)
	if err != nil || len(transitions) != 1 || transitions[0].OperationID != opID {
		t.Fatalf("transitions = %+v err=%v", transitions, err)
	}
}

func testMachineAuthority(spec MachineSpec, root string) MachineAuthority {
	stateDir := filepath.Join(root, spec.MachineID)
	pkiDir := filepath.Join(stateDir, "pki")
	return MachineAuthority{
		MachineID: spec.MachineID, CreationOperationID: "op_aaaaaaaaaaaaaaaaaaaaaaaaaa", OwnerUID: 0,
		HostUsername: "ehjintm-test", HostGroupname: "ehjintm-test", KVMGID: 108,
		StateDirectory: stateDir, RuntimeDirectory: filepath.Join(root, "runtime", spec.MachineID),
		OverlayPath: filepath.Join(stateDir, "root.qcow2"), SeedPath: filepath.Join(stateDir, "cidata.img"), PKIDirectory: pkiDir,
		CACertificatePath: filepath.Join(pkiDir, "ca.crt"), CAPrivateKeyPath: filepath.Join(pkiDir, "ca.key"),
		ControllerCertificatePath: filepath.Join(pkiDir, "controller.crt"), ControllerPrivateKeyPath: filepath.Join(pkiDir, "controller.key"),
		GuestCertificatePath: filepath.Join(pkiDir, "guest.crt"), GuestPrivateKeyPath: filepath.Join(pkiDir, "guest.key"),
		VMMIdentityPath: filepath.Join(stateDir, "vmm-identity.json"), VMMExecutablePath: "/opt/ehjint/cloud-hypervisor",
		FirmwarePath: "/opt/ehjint/hypervisor-fw", BaseImagePath: "/opt/ehjint/ubuntu.img",
		CPUCount: 2, MemoryBytes: 512 << 20, RootDiskBytes: 4 << 30, NetworkDisabled: true,
	}
}
