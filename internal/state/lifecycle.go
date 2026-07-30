package state

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/StealthEyeLLC/ehjint/internal/contracts"
)

var hostIdentityNamePattern = regexp.MustCompile(`^[a-z_][a-z0-9_-]{0,30}$`)

// MachineAuthority is the immutable durable host/resource authority for one machine.
type MachineAuthority struct {
	MachineID                 string    `json:"machine_id"`
	CreationOperationID       string    `json:"creation_operation_id"`
	OwnerUID                  int       `json:"owner_uid"`
	HostUsername              string    `json:"host_username"`
	HostGroupname             string    `json:"host_groupname"`
	KVMGID                    int       `json:"kvm_gid"`
	StateDirectory            string    `json:"state_directory"`
	RuntimeDirectory          string    `json:"runtime_directory"`
	OverlayPath               string    `json:"overlay_path"`
	SeedPath                  string    `json:"seed_path"`
	PKIDirectory              string    `json:"pki_directory"`
	CACertificatePath         string    `json:"ca_certificate_path"`
	CAPrivateKeyPath          string    `json:"ca_private_key_path"`
	ControllerCertificatePath string    `json:"controller_certificate_path"`
	ControllerPrivateKeyPath  string    `json:"controller_private_key_path"`
	GuestCertificatePath      string    `json:"guest_certificate_path"`
	GuestPrivateKeyPath       string    `json:"guest_private_key_path"`
	VMMIdentityPath           string    `json:"vmm_identity_path"`
	VMMExecutablePath         string    `json:"vmm_executable_path"`
	FirmwarePath              string    `json:"firmware_path"`
	BaseImagePath             string    `json:"base_image_path"`
	CPUCount                  int       `json:"cpu_count"`
	MemoryBytes               uint64    `json:"memory_bytes"`
	RootDiskBytes             uint64    `json:"root_disk_bytes"`
	NetworkDisabled           bool      `json:"network_disabled"`
	CreatedAt                 time.Time `json:"created_at"`
	UpdatedAt                 time.Time `json:"updated_at"`
}

// MachineTransition is an append-only durable lifecycle decision.
type MachineTransition struct {
	TransitionID        int64         `json:"transition_id"`
	MachineID           string        `json:"machine_id"`
	PreviousState       ObservedState `json:"previous_state"`
	RequestedState      ObservedState `json:"requested_state"`
	OperationID         string        `json:"operation_id"`
	IdempotencyKey      string        `json:"idempotency_key"`
	TransitionAt        time.Time     `json:"transition_at"`
	ExpectedResources   string        `json:"expected_resources"`
	ObservedResources   string        `json:"observed_resources"`
	FailureCode         string        `json:"failure_code"`
	FailureMessage      string        `json:"failure_message"`
	RecoveryDisposition string        `json:"recovery_disposition"`
}

// AllocateMachine atomically allocates the machine row and every immutable
// host/resource identity. An exact existing allocation is an idempotent replay.
func (store *Store) AllocateMachine(ctx context.Context, spec MachineSpec, authority MachineAuthority) (Machine, MachineAuthority, bool, error) {
	if err := validateMachineSpec(spec); err != nil {
		return Machine{}, MachineAuthority{}, false, err
	}
	if err := validateMachineAuthority(authority, spec.MachineID); err != nil {
		return Machine{}, MachineAuthority{}, false, err
	}
	tx, err := store.db.BeginTx(ctx, nil)
	if err != nil {
		return Machine{}, MachineAuthority{}, false, fmt.Errorf("begin machine resource allocation: %w", err)
	}
	defer tx.Rollback()
	existing, scanErr := scanMachine(tx.QueryRowContext(ctx, `SELECT `+machineColumns+` FROM machines WHERE machine_id = ?`, spec.MachineID))
	if scanErr == nil {
		if !sameMachineSpec(existing, spec) {
			return Machine{}, MachineAuthority{}, false, ErrMachineConflict
		}
		existingAuthority, err := scanMachineAuthority(tx.QueryRowContext(ctx, `SELECT `+machineAuthorityColumns+` FROM machine_authority a WHERE machine_id = ?`, spec.MachineID))
		if err != nil || !sameMachineAuthority(existingAuthority, authority) {
			if err == nil {
				err = ErrMachineConflict
			}
			return Machine{}, MachineAuthority{}, false, err
		}
		if err := tx.Commit(); err != nil {
			return Machine{}, MachineAuthority{}, false, fmt.Errorf("commit machine allocation replay: %w", err)
		}
		return existing, existingAuthority, true, nil
	}
	if !errors.Is(scanErr, ErrNotFound) {
		return Machine{}, MachineAuthority{}, false, scanErr
	}
	now := store.timestamp()
	if _, err := tx.ExecContext(ctx, `
INSERT INTO machines(
 machine_id, stable_name, desired_state, observed_state, manifest_path, manifest_digest,
 creating_release, vmm_version, vmm_digest, guest_image_digest, firmware_digest, overlay_identity,
 vsock_cid, agent_port, vmm_identity, vmm_uid, vmm_gid, api_socket, vsock_socket, created_at, updated_at
) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		spec.MachineID, spec.StableName, string(DesiredStopped), string(ObservedAbsent), spec.ManifestPath, spec.ManifestDigest,
		spec.CreatingRelease, spec.VMMVersion, spec.VMMDigest, spec.GuestImageDigest, spec.FirmwareDigest, spec.OverlayIdentity,
		spec.VsockCID, spec.AgentPort, spec.VMMIdentity, spec.VMMUID, spec.VMMGID, spec.APISocket, spec.VsockSocket, now, now); err != nil {
		return Machine{}, MachineAuthority{}, false, classifyAllocationError(err)
	}
	if _, err := tx.ExecContext(ctx, `
INSERT INTO machine_authority(
 machine_id, creation_operation_id, owner_uid, host_username, host_groupname, kvm_gid,
 state_directory, runtime_directory, overlay_path, seed_path, pki_directory,
 ca_certificate_path, ca_private_key_path, controller_certificate_path, controller_private_key_path,
 guest_certificate_path, guest_private_key_path, vmm_identity_path, vmm_executable_path, firmware_path,
 base_image_path, cpu_count, memory_bytes, root_disk_bytes, network_disabled, created_at, updated_at
) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		authority.MachineID, authority.CreationOperationID, authority.OwnerUID, authority.HostUsername, authority.HostGroupname, authority.KVMGID,
		authority.StateDirectory, authority.RuntimeDirectory, authority.OverlayPath, authority.SeedPath, authority.PKIDirectory,
		authority.CACertificatePath, authority.CAPrivateKeyPath, authority.ControllerCertificatePath, authority.ControllerPrivateKeyPath,
		authority.GuestCertificatePath, authority.GuestPrivateKeyPath, authority.VMMIdentityPath, authority.VMMExecutablePath, authority.FirmwarePath,
		authority.BaseImagePath, authority.CPUCount, authority.MemoryBytes, authority.RootDiskBytes, boolInt(authority.NetworkDisabled), now, now); err != nil {
		return Machine{}, MachineAuthority{}, false, classifyAllocationError(err)
	}
	created, err := scanMachine(tx.QueryRowContext(ctx, `SELECT `+machineColumns+` FROM machines WHERE machine_id = ?`, spec.MachineID))
	if err != nil {
		return Machine{}, MachineAuthority{}, false, err
	}
	createdAuthority, err := scanMachineAuthority(tx.QueryRowContext(ctx, `SELECT `+machineAuthorityColumns+` FROM machine_authority a WHERE machine_id = ?`, spec.MachineID))
	if err != nil {
		return Machine{}, MachineAuthority{}, false, err
	}
	if err := tx.Commit(); err != nil {
		return Machine{}, MachineAuthority{}, false, fmt.Errorf("commit machine resource allocation: %w", err)
	}
	return created, createdAuthority, false, nil
}

// GetMachineAuthority returns immutable host/resource authority by ID or stable name.
func (store *Store) GetMachineAuthority(ctx context.Context, selector string) (MachineAuthority, error) {
	return scanMachineAuthority(store.db.QueryRowContext(ctx, `
SELECT `+machineAuthorityColumns+` FROM machine_authority a
JOIN machines m ON m.machine_id = a.machine_id
WHERE a.machine_id = ? OR m.stable_name = ?`, selector, selector))
}

// TransitionMachineLifecycle atomically appends transition evidence and updates observed truth.
func (store *Store) TransitionMachineLifecycle(ctx context.Context, selector string, to ObservedState, operationID, idempotencyKey, expected, observed, failureCode, failureMessage, disposition string) (Machine, MachineTransition, error) {
	if operationID == "" || idempotencyKey == "" || disposition == "" || len(expected) > 64*1024 || len(observed) > 64*1024 || len(failureCode) > 128 || len(failureMessage) > 1024 || len(disposition) > 256 {
		return Machine{}, MachineTransition{}, fmt.Errorf("invalid lifecycle transition evidence")
	}
	if _, err := contracts.ParseIdentifier(contracts.OperationIDKind, operationID); err != nil {
		return Machine{}, MachineTransition{}, err
	}
	tx, err := store.db.BeginTx(ctx, nil)
	if err != nil {
		return Machine{}, MachineTransition{}, fmt.Errorf("begin machine lifecycle transition: %w", err)
	}
	defer tx.Rollback()
	current, err := scanMachine(tx.QueryRowContext(ctx, `SELECT `+machineColumns+` FROM machines WHERE machine_id = ? OR stable_name = ?`, selector, selector))
	if err != nil {
		return Machine{}, MachineTransition{}, err
	}
	if current.ObservedState != to {
		if err := ValidateObservedTransition(current.ObservedState, to); err != nil {
			return Machine{}, MachineTransition{}, err
		}
	}
	now := store.timestamp()
	result, err := tx.ExecContext(ctx, `
INSERT OR IGNORE INTO machine_transitions(
 machine_id, previous_state, requested_state, operation_id, idempotency_key, transition_at,
 expected_resources, observed_resources, failure_code, failure_message, recovery_disposition
) VALUES(?,?,?,?,?,?,?,?,?,?,?)`, current.MachineID, string(current.ObservedState), string(to), operationID, idempotencyKey, now, expected, observed, failureCode, failureMessage, disposition)
	if err != nil {
		return Machine{}, MachineTransition{}, fmt.Errorf("persist lifecycle transition: %w", err)
	}
	inserted, err := result.RowsAffected()
	if err != nil {
		return Machine{}, MachineTransition{}, fmt.Errorf("read lifecycle transition result: %w", err)
	}
	if inserted == 1 && current.ObservedState != to {
		if _, err := tx.ExecContext(ctx, `UPDATE machines SET observed_state=?, last_failure=?, generation=generation+1, updated_at=? WHERE machine_id=?`, string(to), failureMessage, now, current.MachineID); err != nil {
			return Machine{}, MachineTransition{}, fmt.Errorf("update machine lifecycle state: %w", err)
		}
	}
	transition, err := scanMachineTransition(tx.QueryRowContext(ctx, `SELECT `+machineTransitionColumns+` FROM machine_transitions WHERE operation_id=? AND previous_state=? AND requested_state=?`, operationID, string(current.ObservedState), string(to)))
	if err != nil {
		return Machine{}, MachineTransition{}, err
	}
	updated, err := scanMachine(tx.QueryRowContext(ctx, `SELECT `+machineColumns+` FROM machines WHERE machine_id=?`, current.MachineID))
	if err != nil {
		return Machine{}, MachineTransition{}, err
	}
	if err := tx.Commit(); err != nil {
		return Machine{}, MachineTransition{}, fmt.Errorf("commit lifecycle transition: %w", err)
	}
	return updated, transition, nil
}

func (store *Store) ListMachineTransitions(ctx context.Context, selector string) ([]MachineTransition, error) {
	machine, err := store.GetMachine(ctx, selector)
	if err != nil {
		return nil, err
	}
	rows, err := store.db.QueryContext(ctx, `SELECT `+machineTransitionColumns+` FROM machine_transitions WHERE machine_id=? ORDER BY transition_id`, machine.MachineID)
	if err != nil {
		return nil, fmt.Errorf("list lifecycle transitions: %w", err)
	}
	defer rows.Close()
	var result []MachineTransition
	for rows.Next() {
		item, err := scanMachineTransition(rows)
		if err != nil {
			return nil, err
		}
		result = append(result, item)
	}
	return result, rows.Err()
}

const machineAuthorityColumns = `a.machine_id, a.creation_operation_id, a.owner_uid, a.host_username, a.host_groupname, a.kvm_gid,
 a.state_directory, a.runtime_directory, a.overlay_path, a.seed_path, a.pki_directory,
 a.ca_certificate_path, a.ca_private_key_path, a.controller_certificate_path, a.controller_private_key_path,
 a.guest_certificate_path, a.guest_private_key_path, a.vmm_identity_path, a.vmm_executable_path, a.firmware_path,
 a.base_image_path, a.cpu_count, a.memory_bytes, a.root_disk_bytes, a.network_disabled, a.created_at, a.updated_at`

const machineTransitionColumns = `transition_id, machine_id, previous_state, requested_state, operation_id, idempotency_key,
 transition_at, expected_resources, observed_resources, failure_code, failure_message, recovery_disposition`

func scanMachineAuthority(row rowScanner) (MachineAuthority, error) {
	var a MachineAuthority
	var network int
	var created, updated string
	if err := row.Scan(&a.MachineID, &a.CreationOperationID, &a.OwnerUID, &a.HostUsername, &a.HostGroupname, &a.KVMGID,
		&a.StateDirectory, &a.RuntimeDirectory, &a.OverlayPath, &a.SeedPath, &a.PKIDirectory,
		&a.CACertificatePath, &a.CAPrivateKeyPath, &a.ControllerCertificatePath, &a.ControllerPrivateKeyPath,
		&a.GuestCertificatePath, &a.GuestPrivateKeyPath, &a.VMMIdentityPath, &a.VMMExecutablePath, &a.FirmwarePath,
		&a.BaseImagePath, &a.CPUCount, &a.MemoryBytes, &a.RootDiskBytes, &network, &created, &updated); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return MachineAuthority{}, ErrNotFound
		}
		return MachineAuthority{}, fmt.Errorf("scan machine authority: %w", err)
	}
	a.NetworkDisabled = network == 1
	var err error
	if a.CreatedAt, err = parseTime(created); err != nil {
		return MachineAuthority{}, err
	}
	if a.UpdatedAt, err = parseTime(updated); err != nil {
		return MachineAuthority{}, err
	}
	return a, nil
}

func scanMachineTransition(row rowScanner) (MachineTransition, error) {
	var t MachineTransition
	var previous, requested, at string
	if err := row.Scan(&t.TransitionID, &t.MachineID, &previous, &requested, &t.OperationID, &t.IdempotencyKey,
		&at, &t.ExpectedResources, &t.ObservedResources, &t.FailureCode, &t.FailureMessage, &t.RecoveryDisposition); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return MachineTransition{}, ErrNotFound
		}
		return MachineTransition{}, fmt.Errorf("scan lifecycle transition: %w", err)
	}
	t.PreviousState, t.RequestedState = ObservedState(previous), ObservedState(requested)
	var err error
	if t.TransitionAt, err = parseTime(at); err != nil {
		return MachineTransition{}, err
	}
	return t, nil
}

func validateMachineAuthority(a MachineAuthority, machineID string) error {
	if a.MachineID != machineID {
		return fmt.Errorf("machine authority ID mismatch")
	}
	if _, err := contracts.ParseIdentifier(contracts.OperationIDKind, a.CreationOperationID); err != nil {
		return err
	}
	if a.OwnerUID < 0 || a.KVMGID <= 0 || a.CPUCount <= 0 || a.MemoryBytes < 128<<20 || a.MemoryBytes%4096 != 0 || a.RootDiskBytes < 1<<20 || !a.NetworkDisabled {
		return fmt.Errorf("invalid machine resource authority")
	}
	if !hostIdentityNamePattern.MatchString(a.HostUsername) || !hostIdentityNamePattern.MatchString(a.HostGroupname) {
		return fmt.Errorf("invalid bounded host identity name")
	}
	paths := []string{a.StateDirectory, a.RuntimeDirectory, a.OverlayPath, a.SeedPath, a.PKIDirectory, a.CACertificatePath, a.CAPrivateKeyPath,
		a.ControllerCertificatePath, a.ControllerPrivateKeyPath, a.GuestCertificatePath, a.GuestPrivateKeyPath,
		a.VMMIdentityPath, a.VMMExecutablePath, a.FirmwarePath, a.BaseImagePath}
	for _, path := range paths {
		if path == "" || !filepath.IsAbs(path) || filepath.Clean(path) != path || strings.ContainsRune(path, '\x00') || len(path) >= 4096 {
			return fmt.Errorf("invalid machine authority path")
		}
	}
	return nil
}

func sameMachineAuthority(left, right MachineAuthority) bool {
	left.CreatedAt, left.UpdatedAt, right.CreatedAt, right.UpdatedAt = time.Time{}, time.Time{}, time.Time{}, time.Time{}
	return left == right
}

func classifyAllocationError(err error) error {
	message := strings.ToLower(err.Error())
	if strings.Contains(message, "unique constraint") || strings.Contains(message, "constraint failed") {
		return fmt.Errorf("%w: durable resource collision: %v", ErrMachineConflict, err)
	}
	return fmt.Errorf("persist machine allocation: %w", err)
}

func boolInt(value bool) int {
	if value {
		return 1
	}
	return 0
}
