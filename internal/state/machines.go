package state

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
)

const machineColumns = `machine_id, stable_name, desired_state, observed_state, manifest_path, manifest_digest,
       creating_release, vmm_version, vmm_digest, guest_image_digest, firmware_digest, overlay_identity,
       vsock_cid, agent_port, vmm_identity, vmm_uid, vmm_gid, vmm_pid, process_start_identity,
       api_socket, vsock_socket, guest_boot_id, readiness_state, last_failure, generation, created_at, updated_at`

// EnsureMachine creates one durable machine projection or proves that an exact
// immutable projection already exists. The bool reports an exact replay.
func (store *Store) EnsureMachine(ctx context.Context, spec MachineSpec) (Machine, bool, error) {
	if err := validateMachineSpec(spec); err != nil {
		return Machine{}, false, err
	}
	transaction, err := store.db.BeginTx(ctx, nil)
	if err != nil {
		return Machine{}, false, fmt.Errorf("begin machine creation: %w", err)
	}
	defer transaction.Rollback()
	existing, err := scanMachine(transaction.QueryRowContext(ctx,
		`SELECT `+machineColumns+` FROM machines WHERE machine_id = ?`, spec.MachineID))
	if err == nil {
		if !sameMachineSpec(existing, spec) {
			return Machine{}, false, ErrMachineConflict
		}
		if err := transaction.Commit(); err != nil {
			return Machine{}, false, fmt.Errorf("commit machine replay: %w", err)
		}
		return existing, true, nil
	}
	if !errors.Is(err, ErrNotFound) {
		return Machine{}, false, err
	}
	now := store.timestamp()
	_, err = transaction.ExecContext(ctx, `
INSERT INTO machines(
    machine_id, stable_name, desired_state, observed_state, manifest_path, manifest_digest,
    creating_release, vmm_version, vmm_digest, guest_image_digest, firmware_digest, overlay_identity,
    vsock_cid, agent_port, vmm_identity, vmm_uid, vmm_gid, api_socket, vsock_socket, created_at, updated_at
) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		spec.MachineID, spec.StableName, string(DesiredStopped), string(ObservedAbsent),
		spec.ManifestPath, spec.ManifestDigest, spec.CreatingRelease, spec.VMMVersion, spec.VMMDigest,
		spec.GuestImageDigest, spec.FirmwareDigest, spec.OverlayIdentity, spec.VsockCID, spec.AgentPort,
		spec.VMMIdentity, spec.VMMUID, spec.VMMGID, spec.APISocket, spec.VsockSocket, now, now)
	if err != nil {
		return Machine{}, false, fmt.Errorf("persist machine projection: %w", err)
	}
	created, err := scanMachine(transaction.QueryRowContext(ctx,
		`SELECT `+machineColumns+` FROM machines WHERE machine_id = ?`, spec.MachineID))
	if err != nil {
		return Machine{}, false, err
	}
	if err := transaction.Commit(); err != nil {
		return Machine{}, false, fmt.Errorf("commit machine projection: %w", err)
	}
	return created, false, nil
}

// GetMachine accepts either the typed ID or stable name.
func (store *Store) GetMachine(ctx context.Context, selector string) (Machine, error) {
	if selector == "" {
		return Machine{}, fmt.Errorf("machine selector is required")
	}
	return scanMachine(store.db.QueryRowContext(ctx,
		`SELECT `+machineColumns+` FROM machines WHERE machine_id = ? OR stable_name = ?`, selector, selector))
}

// ListMachines returns stable durable order.
func (store *Store) ListMachines(ctx context.Context) ([]Machine, error) {
	rows, err := store.db.QueryContext(ctx, `SELECT `+machineColumns+` FROM machines ORDER BY stable_name, machine_id`)
	if err != nil {
		return nil, fmt.Errorf("list machines: %w", err)
	}
	defer rows.Close()
	var result []Machine
	for rows.Next() {
		machine, scanErr := scanMachine(rows)
		if scanErr != nil {
			return nil, scanErr
		}
		result = append(result, machine)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate machines: %w", err)
	}
	return result, nil
}

// SetMachineDesired persists requested lifecycle truth.
func (store *Store) SetMachineDesired(ctx context.Context, selector string, desired DesiredState) (Machine, error) {
	if !validDesired(desired) {
		return Machine{}, fmt.Errorf("invalid desired machine state %q", desired)
	}
	result, err := store.db.ExecContext(ctx, `
UPDATE machines SET desired_state = ?, updated_at = ?
WHERE machine_id = ? OR stable_name = ?`, string(desired), store.timestamp(), selector, selector)
	if err != nil {
		return Machine{}, fmt.Errorf("persist desired machine state: %w", err)
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return Machine{}, fmt.Errorf("read desired-state update result: %w", err)
	}
	if rows == 0 {
		return Machine{}, ErrNotFound
	}
	return store.GetMachine(ctx, selector)
}

// TransitionMachineObserved applies one declared observed-state transition.
func (store *Store) TransitionMachineObserved(ctx context.Context, selector string, to ObservedState, failure string) (Machine, error) {
	if len(failure) > 1024 {
		return Machine{}, fmt.Errorf("machine failure message exceeds bound")
	}
	transaction, err := store.db.BeginTx(ctx, nil)
	if err != nil {
		return Machine{}, fmt.Errorf("begin observed-state transition: %w", err)
	}
	defer transaction.Rollback()
	current, err := scanMachine(transaction.QueryRowContext(ctx,
		`SELECT `+machineColumns+` FROM machines WHERE machine_id = ? OR stable_name = ?`, selector, selector))
	if err != nil {
		return Machine{}, err
	}
	if err := ValidateObservedTransition(current.ObservedState, to); err != nil {
		return Machine{}, err
	}
	_, err = transaction.ExecContext(ctx, `
UPDATE machines SET observed_state = ?, last_failure = ?, generation = generation + 1, updated_at = ?
WHERE machine_id = ?`, string(to), failure, store.timestamp(), current.MachineID)
	if err != nil {
		return Machine{}, fmt.Errorf("persist observed machine state: %w", err)
	}
	result, err := scanMachine(transaction.QueryRowContext(ctx,
		`SELECT `+machineColumns+` FROM machines WHERE machine_id = ?`, current.MachineID))
	if err != nil {
		return Machine{}, err
	}
	if err := transaction.Commit(); err != nil {
		return Machine{}, fmt.Errorf("commit observed-state transition: %w", err)
	}
	return result, nil
}

// UpdateRuntimeObservation persists process and guest readiness identity after
// it has been re-observed. A zero PID explicitly clears process ownership.
func (store *Store) UpdateRuntimeObservation(ctx context.Context, selector string, observation RuntimeObservation) (Machine, error) {
	if observation.VMMPID < 0 || len(observation.ProcessStartIdentity) > 256 || len(observation.GuestBootID) > 128 ||
		len(observation.ReadinessState) > 64 || len(observation.LastFailure) > 1024 {
		return Machine{}, fmt.Errorf("invalid or unbounded runtime observation")
	}
	var pid any
	if observation.VMMPID > 0 {
		pid = observation.VMMPID
	}
	result, err := store.db.ExecContext(ctx, `
UPDATE machines SET vmm_pid = ?, process_start_identity = ?, guest_boot_id = ?, readiness_state = ?,
    last_failure = ?, generation = generation + 1, updated_at = ?
WHERE machine_id = ? OR stable_name = ?`, pid, observation.ProcessStartIdentity, observation.GuestBootID,
		observation.ReadinessState, observation.LastFailure, store.timestamp(), selector, selector)
	if err != nil {
		return Machine{}, fmt.Errorf("persist runtime observation: %w", err)
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return Machine{}, fmt.Errorf("read runtime-observation update result: %w", err)
	}
	if rows == 0 {
		return Machine{}, ErrNotFound
	}
	return store.GetMachine(ctx, selector)
}

// DeleteMachineProjection removes metadata only after the durable desired and
// observed states both prove absence and cleanup ownership records are gone.
func (store *Store) DeleteMachineProjection(ctx context.Context, selector string) error {
	machine, err := store.GetMachine(ctx, selector)
	if err != nil {
		return err
	}
	if machine.DesiredState != DesiredAbsent || machine.ObservedState != ObservedAbsent {
		return fmt.Errorf("machine projection cannot be deleted before desired and observed absence")
	}
	result, err := store.db.ExecContext(ctx, `DELETE FROM machines WHERE machine_id = ?`, machine.MachineID)
	if err != nil {
		return fmt.Errorf("delete machine projection: %w", err)
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("read machine deletion result: %w", err)
	}
	if rows != 1 {
		return ErrNotFound
	}
	return nil
}

func validateMachineSpec(spec MachineSpec) error {
	if spec.MachineID == "" || len(spec.MachineID) > 128 || spec.StableName == "" || len(spec.StableName) > 63 {
		return fmt.Errorf("machine ID and bounded stable name are required")
	}
	for name, digest := range map[string]string{
		"manifest": spec.ManifestDigest, "VMM": spec.VMMDigest, "guest image": spec.GuestImageDigest, "firmware": spec.FirmwareDigest,
	} {
		if !digestPattern.MatchString(digest) {
			return fmt.Errorf("%s digest must be lowercase SHA-256", name)
		}
	}
	for name, path := range map[string]string{"manifest": spec.ManifestPath, "API socket": spec.APISocket, "vsock socket": spec.VsockSocket} {
		if !filepath.IsAbs(filepath.Clean(path)) || len(path) > 4096 {
			return fmt.Errorf("%s path must be absolute and bounded", name)
		}
	}
	if strings.TrimSpace(spec.CreatingRelease) == "" || strings.TrimSpace(spec.VMMVersion) == "" ||
		strings.TrimSpace(spec.OverlayIdentity) == "" || strings.TrimSpace(spec.VMMIdentity) == "" {
		return fmt.Errorf("machine immutable identities are required")
	}
	if spec.VsockCID < 3 || spec.AgentPort == 0 || spec.VMMUID <= 0 || spec.VMMGID <= 0 {
		return fmt.Errorf("machine transport and VMM identities are invalid")
	}
	return nil
}

func sameMachineSpec(machine Machine, spec MachineSpec) bool {
	return machine.MachineID == spec.MachineID && machine.StableName == spec.StableName &&
		machine.ManifestPath == spec.ManifestPath && machine.ManifestDigest == spec.ManifestDigest &&
		machine.CreatingRelease == spec.CreatingRelease && machine.VMMVersion == spec.VMMVersion &&
		machine.VMMDigest == spec.VMMDigest && machine.GuestImageDigest == spec.GuestImageDigest &&
		machine.FirmwareDigest == spec.FirmwareDigest && machine.OverlayIdentity == spec.OverlayIdentity &&
		machine.VsockCID == spec.VsockCID && machine.AgentPort == spec.AgentPort &&
		machine.VMMIdentity == spec.VMMIdentity && machine.VMMUID == spec.VMMUID && machine.VMMGID == spec.VMMGID &&
		machine.APISocket == spec.APISocket && machine.VsockSocket == spec.VsockSocket
}

func scanMachine(row rowScanner) (Machine, error) {
	var machine Machine
	var desired, observed string
	var cid, port int64
	var pid sql.NullInt64
	var created, updated string
	if err := row.Scan(
		&machine.MachineID, &machine.StableName, &desired, &observed, &machine.ManifestPath,
		&machine.ManifestDigest, &machine.CreatingRelease, &machine.VMMVersion, &machine.VMMDigest,
		&machine.GuestImageDigest, &machine.FirmwareDigest, &machine.OverlayIdentity, &cid, &port,
		&machine.VMMIdentity, &machine.VMMUID, &machine.VMMGID, &pid, &machine.ProcessStartIdentity,
		&machine.APISocket, &machine.VsockSocket, &machine.GuestBootID, &machine.ReadinessState,
		&machine.LastFailure, &machine.Generation, &created, &updated,
	); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return Machine{}, ErrNotFound
		}
		return Machine{}, fmt.Errorf("scan machine truth: %w", err)
	}
	machine.DesiredState = DesiredState(desired)
	machine.ObservedState = ObservedState(observed)
	machine.VsockCID = uint32(cid)
	machine.AgentPort = uint32(port)
	if pid.Valid {
		machine.VMMPID = int(pid.Int64)
	}
	var err error
	if machine.CreatedAt, err = parseTime(created); err != nil {
		return Machine{}, err
	}
	if machine.UpdatedAt, err = parseTime(updated); err != nil {
		return Machine{}, err
	}
	return machine, nil
}
