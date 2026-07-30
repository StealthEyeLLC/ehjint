// Package machine integrates EHJINT's durable state, deterministic guest
// construction, per-machine host identity, and authenticated controller edge.
package machine

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/StealthEyeLLC/ehjint/internal/atomicfile"
	"github.com/StealthEyeLLC/ehjint/internal/cidata"
	"github.com/StealthEyeLLC/ehjint/internal/contracts"
	"github.com/StealthEyeLLC/ehjint/internal/controller"
	"github.com/StealthEyeLLC/ehjint/internal/controlproto"
	"github.com/StealthEyeLLC/ehjint/internal/guestbuild"
	"github.com/StealthEyeLLC/ehjint/internal/hostidentity"
	"github.com/StealthEyeLLC/ehjint/internal/idgen"
	"github.com/StealthEyeLLC/ehjint/internal/layout"
	"github.com/StealthEyeLLC/ehjint/internal/pki"
	"github.com/StealthEyeLLC/ehjint/internal/qcow2"
	"github.com/StealthEyeLLC/ehjint/internal/state"
)

const (
	OperationCreate  = "machine.create"
	OperationInspect = "machine.inspect"
	AgentPort        = uint32(4050)
)

// IdentityAuthority is the exact host identity surface required by lifecycle orchestration.
type IdentityAuthority interface {
	Plan(context.Context, string, int) (hostidentity.Identity, error)
	Ensure(context.Context, hostidentity.Identity) (hostidentity.Observation, error)
	Observe(context.Context, hostidentity.Identity) (hostidentity.Observation, error)
	Remove(context.Context, hostidentity.Identity) error
}

// Config binds one isolated controller instance to exact assets and managed roots.
type Config struct {
	Paths             layout.Paths
	Store             *state.Store
	IdentityAuthority IdentityAuthority
	ExecutablePath    string
	VMMPath           string
	VMMVersion        string
	VMMDigest         string
	FirmwarePath      string
	FirmwareVersion   string
	FirmwareDigest    string
	BaseImagePath     string
	BaseImageProduct  string
	BaseImageVersion  string
	BaseImageDigest   string
	CreatingReleaseID string
	AgentVersion      string
	KVMGID            int
	Clock             func() time.Time
}

// Manager is the controller-backed durable machine authority.
type Manager struct{ config Config }

// CreateRequest is strict public machine creation input.
type CreateRequest struct {
	Name        string `json:"name"`
	VCPUs       int    `json:"vcpus"`
	MemoryMiB   uint64 `json:"memory_mib"`
	RootDiskGiB uint64 `json:"root_disk_gib"`
}

// InspectRequest selects one durable machine by ID or stable name.
type InspectRequest struct {
	Machine string `json:"machine"`
}

// Result is the bounded public machine projection.
type Result struct {
	Machine             state.Machine             `json:"machine"`
	Authority           state.MachineAuthority    `json:"authority"`
	HostIdentity        hostidentity.Observation  `json:"host_identity"`
	Operation           state.Operation           `json:"operation"`
	PreparationVerified bool                      `json:"preparation_verified"`
	Resources           []state.OwnedResource     `json:"resources"`
	Transitions         []state.MachineTransition `json:"transitions"`
}

func New(config Config) (*Manager, error) {
	if config.Store == nil || config.IdentityAuthority == nil || config.Clock == nil {
		return nil, fmt.Errorf("machine store, identity authority, and clock are required")
	}
	if config.KVMGID <= 0 || config.VMMVersion != "53.0.0" || config.VMMDigest == "" || config.FirmwareDigest == "" || config.BaseImageDigest == "" {
		return nil, fmt.Errorf("exact machine runtime identities are required")
	}
	if _, err := contracts.ParseIdentifier(contracts.ReleaseIDKind, config.CreatingReleaseID); err != nil {
		return nil, err
	}
	for _, path := range []string{config.Paths.Root, config.Paths.State, config.Paths.Machines, config.Paths.Operations, config.Paths.Run, config.Paths.RuntimeMachines,
		config.ExecutablePath, config.VMMPath, config.FirmwarePath, config.BaseImagePath} {
		if !filepath.IsAbs(path) || filepath.Clean(path) != path {
			return nil, fmt.Errorf("machine path is not canonical absolute: %s", path)
		}
	}
	for _, digest := range []string{config.VMMDigest, config.FirmwareDigest, config.BaseImageDigest} {
		if len(digest) != 64 {
			return nil, fmt.Errorf("machine asset digest is invalid")
		}
	}
	return &Manager{config: config}, nil
}

// Handle is the authenticated local-controller operation handler.
func (manager *Manager) Handle(ctx context.Context, request controlproto.Request, peer controller.Peer, responder *controller.Responder) error {
	switch request.Operation {
	case OperationCreate:
		if request.IdempotencyKey == "" {
			return publicError(request.Operation, contracts.CodeInvalidArgument, "idempotency key is required", "")
		}
		var input CreateRequest
		if err := contracts.DecodeStrict(request.Input, &input); err != nil {
			return publicError(request.Operation, contracts.CodeInvalidArgument, "invalid machine create input", "")
		}
		return manager.handleCreate(ctx, request, peer, input, responder)
	case OperationInspect:
		var input InspectRequest
		if err := contracts.DecodeStrict(request.Input, &input); err != nil || input.Machine == "" {
			return publicError(request.Operation, contracts.CodeInvalidArgument, "invalid machine selector", "")
		}
		result, err := manager.Inspect(ctx, input.Machine)
		if err != nil {
			return mapError(request.Operation, err, "")
		}
		return responder.Result(result)
	default:
		return publicError(request.Operation, contracts.CodeUnknownOperation, "machine operation is not implemented", "")
	}
}

func (manager *Manager) handleCreate(ctx context.Context, request controlproto.Request, peer controller.Peer, input CreateRequest, responder *controller.Responder) error {
	digest, err := controlproto.Digest(request)
	if err != nil {
		return publicError(request.Operation, contracts.CodeInvalidArgument, "invalid request digest", "")
	}
	machineID, err := deterministicID(contracts.MachineIDKind, "machine", request.IdempotencyKey, digest)
	if err != nil {
		return err
	}
	operationID, err := deterministicID(contracts.OperationIDKind, request.Operation, request.IdempotencyKey, digest)
	if err != nil {
		return err
	}
	op, replay, err := manager.config.Store.CreateOperation(ctx, state.OperationRequest{
		OperationID: operationID, OperationName: request.Operation, OperationVersion: request.OperationVersion,
		IdempotencyKey: request.IdempotencyKey, RequestDigest: digest, MachineID: machineID,
	})
	if err != nil {
		return mapError(request.Operation, err, operationID)
	}
	if err := responder.Accepted(operationID); err != nil {
		return err
	}
	if replay && contracts.OperationState(op.State).Terminal() {
		if op.State != string(contracts.StateSucceeded) {
			return publicError(request.Operation, contracts.ErrorCode(op.ErrorCode), op.ErrorMessage, operationID)
		}
		result, err := manager.Inspect(ctx, machineID)
		if err != nil {
			return mapError(request.Operation, err, operationID)
		}
		result.Operation = op
		return responder.Result(result)
	}
	if _, err := manager.config.Store.TransitionOperation(ctx, operationID, contracts.StateRunning, state.OperationUpdate{}); err != nil {
		return mapError(request.Operation, err, operationID)
	}
	result, err := manager.Create(ctx, machineID, operationID, request.IdempotencyKey, digest, peer.UID, input)
	if err != nil {
		_, _ = manager.config.Store.TransitionOperation(ctx, operationID, contracts.StateFailed, state.OperationUpdate{ErrorCode: string(codeFor(err)), ErrorMessage: bounded(err.Error(), 1024)})
		return mapError(request.Operation, err, operationID)
	}
	resultPath, err := manager.writeResult(operationID, result)
	if err != nil {
		return mapError(request.Operation, err, operationID)
	}
	op, err = manager.config.Store.TransitionOperation(ctx, operationID, contracts.StateSucceeded, state.OperationUpdate{ResultPath: resultPath})
	if err != nil {
		return mapError(request.Operation, err, operationID)
	}
	result.Operation = op
	return responder.Result(result)
}

// Create prepares exactly one durable stopped machine and is restart-safe.
func (manager *Manager) Create(ctx context.Context, machineID, operationID, idempotencyKey, requestDigest string, ownerUID int, input CreateRequest) (Result, error) {
	if err := validateCreate(input); err != nil {
		return Result{}, err
	}
	if ownerUID != 0 {
		return Result{}, fmt.Errorf("machine lifecycle mutation requires root")
	}
	identity, err := manager.config.IdentityAuthority.Plan(ctx, machineID, manager.config.KVMGID)
	if err != nil {
		return Result{}, err
	}
	machineDir, err := manager.config.Paths.Machine(machineID)
	if err != nil {
		return Result{}, err
	}
	runtimeDir, err := manager.config.Paths.RuntimeMachine(machineID)
	if err != nil {
		return Result{}, err
	}
	manifestPath := filepath.Join(machineDir, "manifest.json")
	overlayPath := filepath.Join(machineDir, "root.qcow2")
	seedPath := filepath.Join(machineDir, "cidata.img")
	pkiDir := filepath.Join(machineDir, "pki")
	manifest := manager.manifest(machineID, input)
	manifestBytes, manifestDigest, err := encodeManifest(manifest)
	if err != nil {
		return Result{}, err
	}
	vsockCID := deterministicCID(machineID)
	authorityRecord := state.MachineAuthority{
		MachineID: machineID, CreationOperationID: operationID, OwnerUID: ownerUID,
		HostUsername: identity.Username, HostGroupname: identity.Groupname, KVMGID: identity.KVMGID,
		StateDirectory: machineDir, RuntimeDirectory: runtimeDir, OverlayPath: overlayPath, SeedPath: seedPath, PKIDirectory: pkiDir,
		CACertificatePath: filepath.Join(pkiDir, "ca.crt"), CAPrivateKeyPath: filepath.Join(pkiDir, "ca.key"),
		ControllerCertificatePath: filepath.Join(pkiDir, "controller.crt"), ControllerPrivateKeyPath: filepath.Join(pkiDir, "controller.key"),
		GuestCertificatePath: filepath.Join(pkiDir, "guest.crt"), GuestPrivateKeyPath: filepath.Join(pkiDir, "guest.key"),
		VMMIdentityPath: filepath.Join(runtimeDir, "vmm-identity.json"), VMMExecutablePath: manager.config.VMMPath,
		FirmwarePath: manager.config.FirmwarePath, BaseImagePath: manager.config.BaseImagePath,
		CPUCount: input.VCPUs, MemoryBytes: input.MemoryMiB << 20, RootDiskBytes: input.RootDiskGiB << 30, NetworkDisabled: true,
	}
	spec := state.MachineSpec{
		MachineID: machineID, StableName: input.Name, ManifestPath: manifestPath, ManifestDigest: manifestDigest,
		CreatingRelease: manager.config.CreatingReleaseID, VMMVersion: manager.config.VMMVersion, VMMDigest: manager.config.VMMDigest,
		GuestImageDigest: manager.config.BaseImageDigest, FirmwareDigest: manager.config.FirmwareDigest,
		OverlayIdentity: manifest.Disks[0].OverlayID, VsockCID: vsockCID, AgentPort: AgentPort,
		VMMIdentity: identity.Username, VMMUID: identity.UID, VMMGID: identity.GID,
		APISocket: filepath.Join(runtimeDir, "api.sock"), VsockSocket: filepath.Join(runtimeDir, "vsock.sock"),
	}
	machine, authorityRecord, _, err := manager.config.Store.AllocateMachine(ctx, spec, authorityRecord)
	if err != nil {
		return Result{}, err
	}
	if machine.ObservedState == state.ObservedStopped {
		return manager.Inspect(ctx, machineID)
	}
	_, _, err = manager.config.Store.TransitionMachineLifecycle(ctx, machineID, state.ObservedPreparing, operationID, idempotencyKey,
		`{"machine_row":true}`, `{"machine_row":true}`, "", "", "continue")
	if err != nil {
		return Result{}, err
	}
	observation, err := manager.config.IdentityAuthority.Ensure(ctx, identity)
	if err != nil {
		return Result{}, err
	}
	if err := manager.ensurePreparationDirectories(authorityRecord, identity); err != nil {
		return Result{}, err
	}
	now := manager.config.Clock().UTC()
	ca, bundle, err := manager.ensurePKI(machineID, authorityRecord, now)
	if err != nil {
		return Result{}, err
	}
	binary, err := os.ReadFile(manager.config.ExecutablePath)
	if err != nil {
		return Result{}, fmt.Errorf("read EHJINT guest binary: %w", err)
	}
	artifacts, err := guestbuild.Build(guestbuild.Spec{MachineID: machineID, Hostname: input.Name, ManifestDigest: manifestDigest,
		AgentVersion: manager.config.AgentVersion, AgentPort: AgentPort, Binary: binary, Authority: ca, Credentials: bundle, Now: now,
		BaseImagePath: manager.config.BaseImagePath, BaseImageFormat: "qcow2", RootDiskBytes: input.RootDiskGiB << 30})
	if err != nil {
		return Result{}, err
	}
	if err := atomicfile.Write(manager.config.Paths.Root, overlayPath, artifacts.Overlay, 0o600, atomicfile.Owner{UID: identity.UID, GID: identity.GID}); err != nil {
		return Result{}, err
	}
	if err := atomicfile.Write(manager.config.Paths.Root, seedPath, artifacts.Seed, 0o400, atomicfile.Owner{UID: identity.UID, GID: identity.GID}); err != nil {
		return Result{}, err
	}
	if err := atomicfile.WriteVerified(manager.config.Paths.Root, manifestPath, manifestBytes, 0o640, atomicfile.Owner{UID: 0, GID: 0}, func(data []byte) error { _, err := contracts.ParseMachineManifest(data); return err }); err != nil {
		return Result{}, err
	}
	if err := manager.recordPreparedResources(ctx, machineID, authorityRecord, identity, manifestDigest, artifacts); err != nil {
		return Result{}, err
	}
	machine, _, err = manager.config.Store.TransitionMachineLifecycle(ctx, machineID, state.ObservedStopped, operationID, idempotencyKey,
		`{"host_identity":true,"overlay":true,"seed":true,"manifest":true,"pki":true}`,
		`{"host_identity":true,"overlay":true,"seed":true,"manifest":true,"pki":true}`, "", "", "continue")
	if err != nil {
		return Result{}, err
	}
	result, err := manager.Inspect(ctx, machineID)
	if err != nil {
		return Result{}, err
	}
	result.HostIdentity = observation
	return result, nil
}

// Inspect reconciles durable preparation truth without inferring runtime truth.
func (manager *Manager) Inspect(ctx context.Context, selector string) (Result, error) {
	machine, err := manager.config.Store.GetMachine(ctx, selector)
	if err != nil {
		return Result{}, err
	}
	authority, err := manager.config.Store.GetMachineAuthority(ctx, machine.MachineID)
	if err != nil {
		return Result{}, err
	}
	identity := identityFrom(machine, authority)
	observation, identityErr := manager.config.IdentityAuthority.Observe(ctx, identity)
	verified := identityErr == nil && manager.ValidatePreparation(ctx, machine, authority) == nil
	resources, err := manager.config.Store.ListResources(ctx, machine.MachineID)
	if err != nil {
		return Result{}, err
	}
	transitions, err := manager.config.Store.ListMachineTransitions(ctx, machine.MachineID)
	if err != nil {
		return Result{}, err
	}
	return Result{Machine: machine, Authority: authority, HostIdentity: observation, PreparationVerified: verified, Resources: resources, Transitions: transitions}, nil
}

// ValidatePreparation fails closed on every retained resource before start.
func (manager *Manager) ValidatePreparation(ctx context.Context, machine state.Machine, authority state.MachineAuthority) error {
	if machine.ObservedState != state.ObservedStopped && machine.ObservedState != state.ObservedStarting && machine.ObservedState != state.ObservedRunning {
		return fmt.Errorf("machine is not prepared")
	}
	if !authority.NetworkDisabled || machine.VsockCID < 3 || machine.AgentPort == 0 {
		return fmt.Errorf("invalid isolated machine resources")
	}
	if _, err := manager.config.IdentityAuthority.Observe(ctx, identityFrom(machine, authority)); err != nil {
		return err
	}
	checks := []struct {
		path     string
		mode     os.FileMode
		uid, gid int
		digest   string
	}{
		{authority.OverlayPath, 0o600, machine.VMMUID, machine.VMMGID, ""}, {authority.SeedPath, 0o400, machine.VMMUID, machine.VMMGID, ""},
		{machine.ManifestPath, 0o640, 0, 0, ""}, {manager.config.VMMPath, 0, -1, -1, manager.config.VMMDigest},
		{manager.config.FirmwarePath, 0, -1, -1, manager.config.FirmwareDigest}, {manager.config.BaseImagePath, 0, -1, -1, manager.config.BaseImageDigest},
	}
	for _, check := range checks {
		if err := verifyFile(check.path, check.mode, check.uid, check.gid, check.digest); err != nil {
			return err
		}
	}
	manifestData, err := os.ReadFile(machine.ManifestPath)
	if err != nil {
		return err
	}
	manifest, err := contracts.ParseMachineManifest(manifestData)
	if err != nil {
		return err
	}
	canonicalManifest, err := contracts.CanonicalJSON(manifestData)
	if err != nil {
		return err
	}
	if digestBytes(canonicalManifest) != machine.ManifestDigest {
		return fmt.Errorf("machine manifest digest mismatch")
	}
	if manifest.MachineID != machine.MachineID || manifest.Name != machine.StableName || manifest.Network.Mode != "none" || len(manifest.Network.Interfaces) != 0 || manifest.VMM.Digest != machine.VMMDigest || manifest.GuestImage.Digest != machine.GuestImageDigest {
		return fmt.Errorf("machine manifest does not match durable truth")
	}
	overlayData, err := os.ReadFile(authority.OverlayPath)
	if err != nil {
		return err
	}
	overlay, err := qcow2.Inspect(overlayData)
	if err != nil {
		return err
	}
	if overlay.BackingFile != authority.BaseImagePath || overlay.BackingFormat != "qcow2" || overlay.VirtualSize != authority.RootDiskBytes {
		return fmt.Errorf("overlay backing identity mismatch")
	}
	seedData, err := os.ReadFile(authority.SeedPath)
	if err != nil {
		return err
	}
	if _, err := cidata.Inspect(seedData); err != nil {
		return err
	}
	for _, path := range []string{authority.CACertificatePath, authority.CAPrivateKeyPath, authority.ControllerCertificatePath, authority.ControllerPrivateKeyPath, authority.GuestCertificatePath, authority.GuestPrivateKeyPath} {
		if err := verifyRegular(path); err != nil {
			return err
		}
	}
	caCert, err := os.ReadFile(authority.CACertificatePath)
	if err != nil {
		return err
	}
	caKey, err := os.ReadFile(authority.CAPrivateKeyPath)
	if err != nil {
		return err
	}
	ca, err := pki.ParseAuthority(caCert, caKey)
	if err != nil {
		return err
	}
	controllerCert, _ := os.ReadFile(authority.ControllerCertificatePath)
	controllerKey, _ := os.ReadFile(authority.ControllerPrivateKeyPath)
	if _, err := pki.ParseCredentials(controllerCert, controllerKey, pki.RoleController, machine.MachineID, ca, manager.config.Clock()); err != nil {
		return err
	}
	guestCert, _ := os.ReadFile(authority.GuestCertificatePath)
	guestKey, _ := os.ReadFile(authority.GuestPrivateKeyPath)
	if _, err := pki.ParseCredentials(guestCert, guestKey, pki.RoleGuest, machine.MachineID, ca, manager.config.Clock()); err != nil {
		return err
	}
	return nil
}

func (manager *Manager) ensurePKI(machineID string, authority state.MachineAuthority, now time.Time) (pki.Authority, pki.MachineBundle, error) {
	paths := []string{authority.CACertificatePath, authority.CAPrivateKeyPath, authority.ControllerCertificatePath,
		authority.ControllerPrivateKeyPath, authority.GuestCertificatePath, authority.GuestPrivateKeyPath}
	present := 0
	for _, path := range paths {
		info, err := os.Lstat(path)
		switch {
		case err == nil:
			if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
				return pki.Authority{}, pki.MachineBundle{}, fmt.Errorf("machine PKI path is not a regular file: %s", path)
			}
			present++
		case errors.Is(err, os.ErrNotExist):
		default:
			return pki.Authority{}, pki.MachineBundle{}, fmt.Errorf("inspect machine PKI: %w", err)
		}
	}
	if present != 0 && present != len(paths) {
		return pki.Authority{}, pki.MachineBundle{}, fmt.Errorf("partial machine PKI requires reconciliation")
	}
	if present == 0 {
		ca, err := pki.GenerateAuthority(now, 5*365*24*time.Hour)
		if err != nil {
			return pki.Authority{}, pki.MachineBundle{}, err
		}
		bundle, err := ca.IssueMachine(machineID, now, 365*24*time.Hour)
		if err != nil {
			return pki.Authority{}, pki.MachineBundle{}, err
		}
		if err := pki.WriteAuthority(manager.config.Paths.Root, authority.PKIDirectory, ca, atomicfile.Owner{UID: 0, GID: 0}); err != nil {
			return pki.Authority{}, pki.MachineBundle{}, err
		}
		if err := pki.WriteMachineBundle(manager.config.Paths.Root, authority.PKIDirectory, bundle, ca, atomicfile.Owner{UID: 0, GID: 0}); err != nil {
			return pki.Authority{}, pki.MachineBundle{}, err
		}
		return ca, bundle, nil
	}
	caCert, err := os.ReadFile(authority.CACertificatePath)
	if err != nil {
		return pki.Authority{}, pki.MachineBundle{}, err
	}
	caKey, err := os.ReadFile(authority.CAPrivateKeyPath)
	if err != nil {
		return pki.Authority{}, pki.MachineBundle{}, err
	}
	ca, err := pki.ParseAuthority(caCert, caKey)
	if err != nil {
		return pki.Authority{}, pki.MachineBundle{}, fmt.Errorf("adopt machine CA: %w", err)
	}
	controllerCert, err := os.ReadFile(authority.ControllerCertificatePath)
	if err != nil {
		return pki.Authority{}, pki.MachineBundle{}, err
	}
	controllerKey, err := os.ReadFile(authority.ControllerPrivateKeyPath)
	if err != nil {
		return pki.Authority{}, pki.MachineBundle{}, err
	}
	controllerCredentials, err := pki.ParseCredentials(controllerCert, controllerKey, pki.RoleController, machineID, ca, now)
	if err != nil {
		return pki.Authority{}, pki.MachineBundle{}, fmt.Errorf("adopt controller credentials: %w", err)
	}
	guestCert, err := os.ReadFile(authority.GuestCertificatePath)
	if err != nil {
		return pki.Authority{}, pki.MachineBundle{}, err
	}
	guestKey, err := os.ReadFile(authority.GuestPrivateKeyPath)
	if err != nil {
		return pki.Authority{}, pki.MachineBundle{}, err
	}
	guestCredentials, err := pki.ParseCredentials(guestCert, guestKey, pki.RoleGuest, machineID, ca, now)
	if err != nil {
		return pki.Authority{}, pki.MachineBundle{}, fmt.Errorf("adopt guest credentials: %w", err)
	}
	return ca, pki.MachineBundle{Controller: controllerCredentials, Guest: guestCredentials}, nil
}

func (manager *Manager) manifest(machineID string, input CreateRequest) contracts.MachineManifest {
	overlayID := "root-" + strings.TrimPrefix(machineID, "mach_")[:20]
	return contracts.MachineManifest{SchemaVersion: 1, MachineID: machineID, Name: input.Name, Architecture: "x86_64",
		VMM:        contracts.ComponentBinding{Provider: "cloud-hypervisor", Version: manager.config.VMMVersion, Digest: manager.config.VMMDigest},
		Firmware:   contracts.ComponentBinding{Provider: "rust-hypervisor-firmware", Version: manager.config.FirmwareVersion, Digest: manager.config.FirmwareDigest},
		GuestImage: contracts.ComponentBinding{Provider: "ubuntu-minimal", Version: manager.config.BaseImageVersion, Digest: manager.config.BaseImageDigest}, GuestAgentVersion: manager.config.AgentVersion,
		CPU: contracts.CPUConfiguration{VCPUs: input.VCPUs, Mode: "generic"}, Memory: contracts.MemoryConfiguration{Bytes: input.MemoryMiB << 20, HugePages: false},
		Disks:           []contracts.DiskBinding{{ID: "root", Role: "root", Format: "qcow2", BaseDigest: manager.config.BaseImageDigest, OverlayID: overlayID}},
		Network:         contracts.NetworkTopology{Mode: "none", Interfaces: []contracts.NetworkInterfaceBinding{}},
		Devices:         []contracts.DeviceBinding{{Kind: "vsock", HostReference: "machine-bound-unix-socket", GuestReference: strconv.FormatUint(uint64(AgentPort), 10), Required: true}},
		CapabilityPacks: []string{}, Workspace: contracts.WorkspaceBinding{Mode: "contained", References: []string{}}, SnapshotLineage: contracts.SnapshotLineage{},
		RequiredHostCapabilities: []string{"kvm", "vhost_vsock"}, CreatingReleaseID: manager.config.CreatingReleaseID}
}

func (manager *Manager) ensurePreparationDirectories(a state.MachineAuthority, identity hostidentity.Identity) error {
	for _, item := range []struct {
		path     string
		mode     os.FileMode
		uid, gid int
	}{{manager.config.Paths.State, 0o750, 0, 0}, {manager.config.Paths.Machines, 0o750, 0, 0}, {manager.config.Paths.Operations, 0o750, 0, 0}, {manager.config.Paths.Run, 0o750, 0, 0}, {manager.config.Paths.RuntimeMachines, 0o750, 0, 0}, {a.StateDirectory, 0o750, 0, identity.GID}, {a.PKIDirectory, 0o700, 0, 0}} {
		if err := ensureDirectory(manager.config.Paths.Root, item.path, item.mode, item.uid, item.gid); err != nil {
			return err
		}
	}
	return nil
}
func (manager *Manager) recordPreparedResources(ctx context.Context, machineID string, a state.MachineAuthority, identity hostidentity.Identity, digest string, artifacts guestbuild.Artifacts) error {
	uid, gid := identity.UID, identity.GID
	resources := []state.OwnedResource{
		{MachineID: machineID, Kind: "machine_identity", Path: "identity:" + identity.Username, Identity: machineID, UID: &uid, GID: &gid},
		{MachineID: machineID, Kind: "directory", Path: a.StateDirectory, Identity: machineID, UID: intPtr(0), GID: &gid},
		{MachineID: machineID, Kind: "overlay", Path: a.OverlayPath, Identity: artifacts.OverlayMetadata.BackingFile, Digest: digestBytes(artifacts.Overlay), UID: &uid, GID: &gid},
		{MachineID: machineID, Kind: "seed", Path: a.SeedPath, Identity: "CIDATA:FAT16", Digest: digestBytes(artifacts.Seed), UID: &uid, GID: &gid},
		{MachineID: machineID, Kind: "file", Path: filepath.Join(a.StateDirectory, "manifest.json"), Identity: machineID, Digest: digest, UID: intPtr(0), GID: intPtr(0)},
		{MachineID: machineID, Kind: "directory", Path: a.PKIDirectory, Identity: machineID, UID: intPtr(0), GID: intPtr(0)},
	}
	for _, resource := range resources {
		if _, _, err := manager.config.Store.RecordResource(ctx, resource); err != nil {
			return err
		}
	}
	return nil
}
func (manager *Manager) writeResult(operationID string, result Result) (string, error) {
	dir, err := manager.config.Paths.Operation(operationID)
	if err != nil {
		return "", err
	}
	if err := ensureDirectory(manager.config.Paths.Root, dir, 0o700, 0, 0); err != nil {
		return "", err
	}
	path := filepath.Join(dir, "result.json")
	err = atomicfile.WriteJSON(manager.config.Paths.Root, path, result, 0o600, atomicfile.Owner{UID: 0, GID: 0}, nil)
	return path, err
}

func identityFrom(machine state.Machine, a state.MachineAuthority) hostidentity.Identity {
	return hostidentity.Identity{MachineID: machine.MachineID, Username: a.HostUsername, Groupname: a.HostGroupname, UID: machine.VMMUID, GID: machine.VMMGID, KVMGID: a.KVMGID, Shell: "/usr/sbin/nologin", Home: "/nonexistent", SupplementaryGIDs: []int{a.KVMGID}}
}
func validateCreate(input CreateRequest) error {
	if err := contracts.ValidateMachineName(input.Name); err != nil {
		return err
	}
	if input.VCPUs < 1 || input.VCPUs > 64 {
		return fmt.Errorf("vcpus must be 1..64")
	}
	if input.MemoryMiB < 256 || input.MemoryMiB > 262144 || input.MemoryMiB%1 != 0 {
		return fmt.Errorf("memory_mib must be 256..262144")
	}
	if input.RootDiskGiB < 4 || input.RootDiskGiB > 2048 {
		return fmt.Errorf("root_disk_gib must be 4..2048")
	}
	return nil
}
func encodeManifest(manifest contracts.MachineManifest) ([]byte, string, error) {
	if err := manifest.Validate(); err != nil {
		return nil, "", err
	}
	data, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return nil, "", err
	}
	data = append(data, '\n')
	canonical, err := contracts.CanonicalJSON(data)
	if err != nil {
		return nil, "", err
	}
	sum := sha256.Sum256(canonical)
	return data, hex.EncodeToString(sum[:]), nil
}
func deterministicID(kind contracts.IDKind, parts ...string) (string, error) {
	sum := sha256.Sum256([]byte(strings.Join(parts, "\x00")))
	return idgen.FromReader(kind, bytes.NewReader(sum[:16]))
}
func deterministicCID(machineID string) uint32 {
	sum := sha256.Sum256([]byte(machineID))
	return 4096 + uint32(sum[0])<<16 + uint32(sum[1])<<8 + uint32(sum[2])
}
func digestBytes(data []byte) string { sum := sha256.Sum256(data); return hex.EncodeToString(sum[:]) }
func intPtr(value int) *int          { return &value }
func bounded(value string, limit int) string {
	if len(value) > limit {
		return value[:limit]
	}
	return value
}
func codeFor(err error) contracts.ErrorCode {
	switch {
	case errors.Is(err, state.ErrNotFound):
		return contracts.CodeNotFound
	case errors.Is(err, state.ErrIdempotencyConflict), errors.Is(err, state.ErrMachineConflict):
		return contracts.CodeConflict
	default:
		return contracts.CodeFailedPrecondition
	}
}
func mapError(operation string, err error, operationID string) error {
	return publicError(operation, codeFor(err), bounded(err.Error(), 1024), operationID)
}
func publicError(operation string, code contracts.ErrorCode, message, operationID string) error {
	return &controller.PublicError{Envelope: contracts.ErrorEnvelope{SchemaVersion: 1, Code: code, Message: message, Operation: operation, OperationID: operationID, Retryable: false}}
}
func verifyRegular(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("inspect %s: %w", path, err)
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("machine path is not a regular file: %s", path)
	}
	return nil
}
func verifyFile(path string, mode os.FileMode, uid, gid int, digest string) error {
	if err := verifyRegular(path); err != nil {
		return err
	}
	info, _ := os.Stat(path)
	if mode != 0 && info.Mode().Perm() != mode {
		return fmt.Errorf("wrong file mode for %s", path)
	}
	if stat, ok := info.Sys().(*syscall.Stat_t); ok {
		if uid >= 0 && int(stat.Uid) != uid {
			return fmt.Errorf("wrong file owner for %s", path)
		}
		if gid >= 0 && int(stat.Gid) != gid {
			return fmt.Errorf("wrong file group for %s", path)
		}
	}
	if digest != "" {
		file, err := os.Open(path)
		if err != nil {
			return err
		}
		defer file.Close()
		hash := sha256.New()
		if _, err := io.Copy(hash, file); err != nil {
			return err
		}
		if hex.EncodeToString(hash.Sum(nil)) != digest {
			return fmt.Errorf("digest mismatch for %s", path)
		}
	}
	return nil
}
func ensureDirectory(root, path string, mode os.FileMode, uid, gid int) error {
	if !filepath.IsAbs(root) || !filepath.IsAbs(path) || (path != root && !layout.Within(root, path)) {
		return fmt.Errorf("directory escapes managed root")
	}
	rel, err := filepath.Rel(root, path)
	if err != nil {
		return err
	}
	current := root
	for _, part := range strings.Split(rel, string(filepath.Separator)) {
		if part == "" || part == "." {
			continue
		}
		current = filepath.Join(current, part)
		info, err := os.Lstat(current)
		if errors.Is(err, os.ErrNotExist) {
			if err := os.Mkdir(current, 0o750); err != nil {
				return err
			}
			continue
		}
		if err != nil {
			return err
		}
		if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o002 != 0 {
			return fmt.Errorf("unsafe directory component %s", current)
		}
	}
	if err := os.Chmod(path, mode); err != nil {
		return err
	}
	if err := os.Chown(path, uid, gid); err != nil {
		return err
	}
	return nil
}
