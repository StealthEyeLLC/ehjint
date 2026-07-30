package machine

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/StealthEyeLLC/ehjint/internal/contracts"
	"github.com/StealthEyeLLC/ehjint/internal/controller"
	"github.com/StealthEyeLLC/ehjint/internal/controlproto"
	"github.com/StealthEyeLLC/ehjint/internal/hostidentity"
	"github.com/StealthEyeLLC/ehjint/internal/layout"
	"github.com/StealthEyeLLC/ehjint/internal/state"
)

type fakeIdentityAuthority struct {
	uid      int
	gid      int
	kvmGID   int
	observed map[string]hostidentity.Identity
}

func (authority *fakeIdentityAuthority) Plan(_ context.Context, machineID string, kvmGID int) (hostidentity.Identity, error) {
	candidate, err := hostidentity.Candidate(machineID, kvmGID, 0)
	if err != nil {
		return hostidentity.Identity{}, err
	}
	candidate.UID = authority.uid
	candidate.GID = authority.gid
	candidate.KVMGID = authority.kvmGID
	candidate.SupplementaryGIDs = []int{authority.kvmGID}
	return candidate, nil
}
func (authority *fakeIdentityAuthority) Ensure(ctx context.Context, identity hostidentity.Identity) (hostidentity.Observation, error) {
	authority.observed[identity.MachineID] = identity
	return authority.Observe(ctx, identity)
}
func (authority *fakeIdentityAuthority) Observe(_ context.Context, identity hostidentity.Identity) (hostidentity.Observation, error) {
	observed, ok := authority.observed[identity.MachineID]
	if !ok || !reflect.DeepEqual(observed, identity) {
		return hostidentity.Observation{}, os.ErrNotExist
	}
	return hostidentity.Observation{Identity: identity, UserPresent: true, GroupPresent: true, PasswordLocked: true}, nil
}
func (authority *fakeIdentityAuthority) Remove(_ context.Context, identity hostidentity.Identity) error {
	delete(authority.observed, identity.MachineID)
	return nil
}

func TestCreateInspectReplayAndPreparationRefusal(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("machine preparation ownership test requires root")
	}
	ctx := context.Background()
	root := t.TempDir()
	paths := layout.UnderRoot(root)
	for _, directory := range []string{paths.State, paths.Machines, paths.Operations, paths.Run, paths.RuntimeMachines} {
		if err := os.MkdirAll(directory, 0o750); err != nil {
			t.Fatal(err)
		}
	}
	store, err := state.Open(ctx, filepath.Join(paths.State, "controller.sqlite3"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	vmm := filepath.Join(root, "assets", "cloud-hypervisor")
	firmware := filepath.Join(root, "assets", "hypervisor-fw")
	base := filepath.Join(root, "assets", "ubuntu-minimal.img")
	if err := os.MkdirAll(filepath.Dir(vmm), 0o755); err != nil {
		t.Fatal(err)
	}
	writeTestAsset(t, vmm, []byte("cloud-hypervisor-v53"), 0o755)
	writeTestAsset(t, firmware, []byte("rust-hypervisor-firmware-0.5.0"), 0o644)
	writeTestAsset(t, base, []byte("official-ubuntu-minimal-qcow2"), 0o644)

	authority := &fakeIdentityAuthority{uid: 61000, gid: 61000, kvmGID: 108, observed: map[string]hostidentity.Identity{}}
	now := time.Now().UTC().Truncate(time.Second)
	manager, err := New(Config{
		Paths: paths, Store: store, IdentityAuthority: authority, ExecutablePath: executable,
		VMMPath: vmm, VMMVersion: "53.0.0", VMMDigest: digestFile(t, vmm),
		FirmwarePath: firmware, FirmwareVersion: "0.5.0", FirmwareDigest: digestFile(t, firmware),
		BaseImagePath: base, BaseImageProduct: "Ubuntu Minimal", BaseImageVersion: "24.04-release-20250725", BaseImageDigest: digestFile(t, base),
		CreatingReleaseID: "rel_aaaaaaaaaaaaaaaaaaaaaaaaaa", AgentVersion: "0.0.0-dev", KVMGID: 108,
		Clock: func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}
	machineID, err := deterministicID(contracts.MachineIDKind, "machine-test")
	if err != nil {
		t.Fatal(err)
	}
	operationID, err := deterministicID(contracts.OperationIDKind, "operation-test")
	if err != nil {
		t.Fatal(err)
	}
	input := CreateRequest{Name: "acceptance-machine", VCPUs: 2, MemoryMiB: 512, RootDiskGiB: 4}
	result, err := manager.Create(ctx, machineID, operationID, "create-key", digestBytes([]byte("request")), 0, input)
	if err != nil {
		t.Fatal(err)
	}
	if result.Machine.ObservedState != state.ObservedStopped || !result.PreparationVerified || len(result.Resources) < 6 {
		t.Fatalf("prepared result = %+v", result)
	}
	caDigest := digestFile(t, result.Authority.CAPrivateKeyPath)
	replay, err := manager.Create(ctx, machineID, operationID, "create-key", digestBytes([]byte("request")), 0, input)
	if err != nil {
		t.Fatal(err)
	}
	if replay.Machine.MachineID != machineID || digestFile(t, replay.Authority.CAPrivateKeyPath) != caDigest {
		t.Fatal("idempotent replay changed machine identity or PKI")
	}
	if err := os.Chmod(result.Authority.SeedPath, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := manager.ValidatePreparation(ctx, result.Machine, result.Authority); err == nil {
		t.Fatal("writable CIDATA was accepted")
	}
}

func TestCreateRejectsNonRootAndUnsafeInputs(t *testing.T) {
	if err := validateCreate(CreateRequest{Name: "../escape", VCPUs: 2, MemoryMiB: 512, RootDiskGiB: 4}); err == nil {
		t.Fatal("path-like machine name accepted")
	}
	if err := validateCreate(CreateRequest{Name: "valid-name", VCPUs: 0, MemoryMiB: 512, RootDiskGiB: 4}); err == nil {
		t.Fatal("zero vCPU accepted")
	}
}

func writeTestAsset(t *testing.T, path string, data []byte, mode os.FileMode) {
	t.Helper()
	if err := os.WriteFile(path, data, mode); err != nil {
		t.Fatal(err)
	}
}
func digestFile(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func TestPublicControllerCreateAndInspect(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("controller machine preparation test requires root")
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	root := t.TempDir()
	paths := layout.UnderRoot(root)
	for _, directory := range []string{paths.State, paths.Machines, paths.Operations, paths.Run, paths.RuntimeMachines} {
		if err := os.MkdirAll(directory, 0o750); err != nil {
			t.Fatal(err)
		}
	}
	store, err := state.Open(ctx, filepath.Join(paths.State, "controller.sqlite3"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	assets := filepath.Join(root, "assets")
	if err := os.MkdirAll(assets, 0o755); err != nil {
		t.Fatal(err)
	}
	vmm := filepath.Join(assets, "cloud-hypervisor")
	firmware := filepath.Join(assets, "hypervisor-fw")
	base := filepath.Join(assets, "ubuntu-minimal.img")
	writeTestAsset(t, vmm, []byte("cloud-hypervisor-v53"), 0o755)
	writeTestAsset(t, firmware, []byte("rust-hypervisor-firmware-0.5.0"), 0o644)
	writeTestAsset(t, base, []byte("official-ubuntu-minimal-qcow2"), 0o644)
	authority := &fakeIdentityAuthority{uid: 61001, gid: 61001, kvmGID: 108, observed: map[string]hostidentity.Identity{}}
	manager, err := New(Config{
		Paths: paths, Store: store, IdentityAuthority: authority, ExecutablePath: executable,
		VMMPath: vmm, VMMVersion: "53.0.0", VMMDigest: digestFile(t, vmm),
		FirmwarePath: firmware, FirmwareVersion: "0.5.0", FirmwareDigest: digestFile(t, firmware),
		BaseImagePath: base, BaseImageProduct: "Ubuntu Minimal", BaseImageVersion: "24.04-release-20250725", BaseImageDigest: digestFile(t, base),
		CreatingReleaseID: "rel_aaaaaaaaaaaaaaaaaaaaaaaaaa", AgentVersion: "0.0.0-dev", KVMGID: 108,
		Clock: func() time.Time { return time.Now().UTC() },
	})
	if err != nil {
		t.Fatal(err)
	}
	server, err := controller.NewServer(controller.ServerConfig{
		Paths: paths, SocketUID: 0, SocketGID: 0,
		Policy:  controller.Policy{GroupID: 0, RootOnly: map[string]bool{OperationCreate: true, OperationInspect: true}},
		Handler: manager,
		ValidateOperation: func(name string, version int) error {
			if version != 1 || (name != OperationCreate && name != OperationInspect) {
				return os.ErrInvalid
			}
			return nil
		},
		RequestTimeout: 30 * time.Second, MaxConnections: 4,
	})
	if err != nil {
		t.Fatal(err)
	}
	serveDone := make(chan error, 1)
	go func() { serveDone <- server.ListenAndServe(ctx) }()
	waitForTestSocket(t, paths.ControllerSocket, serveDone)

	createInput, _ := json.Marshal(CreateRequest{Name: "public-machine", VCPUs: 2, MemoryMiB: 512, RootDiskGiB: 4})
	createID, err := controller.NewRequestID()
	if err != nil {
		t.Fatal(err)
	}
	createResult, err := controller.Call(ctx, paths.ControllerSocket, controlproto.Request{
		ProtocolVersion: controlproto.Version, RequestID: createID, Operation: OperationCreate, OperationVersion: 1,
		IdempotencyKey: "public-create-key", Invocation: "ehjint", TimeoutMillis: 30000, Input: createInput,
	}, controller.Streams{})
	if err != nil {
		t.Fatal(err)
	}
	var created Result
	if err := json.Unmarshal(createResult.Payload, &created); err != nil {
		t.Fatal(err)
	}
	if createResult.OperationID == "" || created.Machine.StableName != "public-machine" || !created.PreparationVerified {
		t.Fatalf("public create result = operation=%q payload=%+v", createResult.OperationID, created)
	}

	inspectInput, _ := json.Marshal(InspectRequest{Machine: "public-machine"})
	inspectID, err := controller.NewRequestID()
	if err != nil {
		t.Fatal(err)
	}
	inspectResult, err := controller.Call(ctx, paths.ControllerSocket, controlproto.Request{
		ProtocolVersion: controlproto.Version, RequestID: inspectID, Operation: OperationInspect, OperationVersion: 1,
		Invocation: "ehjint", TimeoutMillis: 30000, Input: inspectInput,
	}, controller.Streams{})
	if err != nil {
		t.Fatal(err)
	}
	var inspected Result
	if err := json.Unmarshal(inspectResult.Payload, &inspected); err != nil {
		t.Fatal(err)
	}
	if inspected.Machine.MachineID != created.Machine.MachineID || !inspected.PreparationVerified {
		t.Fatalf("public inspect result = %+v", inspected)
	}
	cancel()
	select {
	case err := <-serveDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("controller did not stop")
	}
}

func waitForTestSocket(t *testing.T, path string, serveDone <-chan error) {
	t.Helper()
	deadline := time.NewTimer(5 * time.Second)
	defer deadline.Stop()
	ticker := time.NewTicker(5 * time.Millisecond)
	defer ticker.Stop()
	for {
		if info, err := os.Lstat(path); err == nil && info.Mode()&os.ModeSocket != 0 {
			return
		}
		select {
		case err := <-serveDone:
			t.Fatalf("controller exited before socket readiness: %v", err)
		case <-deadline.C:
			t.Fatal("controller socket did not become ready")
		case <-ticker.C:
		}
	}
}
