package state

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"

	"github.com/StealthEyeLLC/ehjint/internal/contracts"
)

const operationColumns = `operation_id, operation_name, operation_version, idempotency_key, request_digest,
       COALESCE(machine_id, ''), state, cancellation_requested, result_path, error_code, error_message,
       stdout_path, stderr_path, stdout_cursor, stderr_cursor, created_at, updated_at, started_at, finished_at`

type rowScanner interface {
	Scan(dest ...any) error
}

// CreateOperation atomically resolves idempotency and persists accepted truth
// before a caller performs any mutation. The bool reports an exact replay.
func (store *Store) CreateOperation(ctx context.Context, request OperationRequest) (Operation, bool, error) {
	if err := validateOperationRequest(request); err != nil {
		return Operation{}, false, err
	}
	transaction, err := store.db.BeginTx(ctx, nil)
	if err != nil {
		return Operation{}, false, fmt.Errorf("begin operation creation: %w", err)
	}
	defer transaction.Rollback()

	existing, err := scanOperation(transaction.QueryRowContext(ctx,
		`SELECT `+operationColumns+` FROM operations WHERE idempotency_key = ?`, request.IdempotencyKey))
	if err == nil {
		if !sameOperationRequest(existing, request) {
			return Operation{}, false, ErrIdempotencyConflict
		}
		if err := transaction.Commit(); err != nil {
			return Operation{}, false, fmt.Errorf("commit operation replay: %w", err)
		}
		return existing, true, nil
	}
	if !errors.Is(err, ErrNotFound) {
		return Operation{}, false, err
	}

	now := store.timestamp()
	var machineID any
	if request.MachineID != "" {
		machineID = request.MachineID
	}
	_, err = transaction.ExecContext(ctx, `
INSERT INTO operations(
    operation_id, operation_name, operation_version, idempotency_key, request_digest, machine_id,
    state, cancellation_requested, created_at, updated_at
) VALUES(?, ?, ?, ?, ?, ?, ?, 0, ?, ?)`,
		request.OperationID, request.OperationName, request.OperationVersion, request.IdempotencyKey,
		request.RequestDigest, machineID, string(contracts.StateAccepted), now, now)
	if err != nil {
		return Operation{}, false, fmt.Errorf("persist accepted operation: %w", err)
	}
	created, err := scanOperation(transaction.QueryRowContext(ctx,
		`SELECT `+operationColumns+` FROM operations WHERE operation_id = ?`, request.OperationID))
	if err != nil {
		return Operation{}, false, err
	}
	if err := transaction.Commit(); err != nil {
		return Operation{}, false, fmt.Errorf("commit accepted operation: %w", err)
	}
	return created, false, nil
}

// GetOperation returns current durable truth.
func (store *Store) GetOperation(ctx context.Context, operationID string) (Operation, error) {
	if operationID == "" {
		return Operation{}, fmt.Errorf("operation ID is required")
	}
	return scanOperation(store.db.QueryRowContext(ctx,
		`SELECT `+operationColumns+` FROM operations WHERE operation_id = ?`, operationID))
}

// ListNonterminalOperations reconstructs recovery work without an in-memory
// operation map.
func (store *Store) ListNonterminalOperations(ctx context.Context) ([]Operation, error) {
	rows, err := store.db.QueryContext(ctx, `SELECT `+operationColumns+`
FROM operations WHERE state IN ('accepted','running') ORDER BY created_at, operation_id`)
	if err != nil {
		return nil, fmt.Errorf("list nonterminal operations: %w", err)
	}
	defer rows.Close()
	var result []Operation
	for rows.Next() {
		operation, scanErr := scanOperation(rows)
		if scanErr != nil {
			return nil, scanErr
		}
		result = append(result, operation)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate nonterminal operations: %w", err)
	}
	return result, nil
}

// TransitionOperation applies one declared operation-state transition. Terminal
// rows cannot be reopened or rewritten.
func (store *Store) TransitionOperation(ctx context.Context, operationID string, to contracts.OperationState, update OperationUpdate) (Operation, error) {
	if !contracts.ValidOperationState(to) {
		return Operation{}, fmt.Errorf("invalid target operation state %q", to)
	}
	if len(update.ErrorCode) > 128 || len(update.ErrorMessage) > 1024 || len(update.ResultPath) > 4096 {
		return Operation{}, fmt.Errorf("operation terminal metadata exceeds bounds")
	}
	transaction, err := store.db.BeginTx(ctx, nil)
	if err != nil {
		return Operation{}, fmt.Errorf("begin operation transition: %w", err)
	}
	defer transaction.Rollback()
	current, err := scanOperation(transaction.QueryRowContext(ctx,
		`SELECT `+operationColumns+` FROM operations WHERE operation_id = ?`, operationID))
	if err != nil {
		return Operation{}, err
	}
	from := contracts.OperationState(current.State)
	if from == to {
		if err := transaction.Commit(); err != nil {
			return Operation{}, fmt.Errorf("commit idempotent operation transition: %w", err)
		}
		return current, nil
	}
	if from.Terminal() {
		return Operation{}, ErrTerminalOperation
	}
	if err := contracts.ValidateTransition(from, to); err != nil {
		return Operation{}, err
	}
	now := store.timestamp()
	started := any(nil)
	finished := any(nil)
	if current.StartedAt != nil {
		started = current.StartedAt.UTC().Format(timeFormat)
	} else if to == contracts.StateRunning {
		started = now
	}
	if current.FinishedAt != nil {
		finished = current.FinishedAt.UTC().Format(timeFormat)
	} else if to.Terminal() {
		finished = now
	}
	_, err = transaction.ExecContext(ctx, `
UPDATE operations SET state = ?, result_path = ?, error_code = ?, error_message = ?,
    updated_at = ?, started_at = ?, finished_at = ?
WHERE operation_id = ?`, string(to), update.ResultPath, update.ErrorCode, update.ErrorMessage,
		now, started, finished, operationID)
	if err != nil {
		return Operation{}, fmt.Errorf("persist operation transition: %w", err)
	}
	result, err := scanOperation(transaction.QueryRowContext(ctx,
		`SELECT `+operationColumns+` FROM operations WHERE operation_id = ?`, operationID))
	if err != nil {
		return Operation{}, err
	}
	if err := transaction.Commit(); err != nil {
		return Operation{}, fmt.Errorf("commit operation transition: %w", err)
	}
	return result, nil
}

const timeFormat = "2006-01-02T15:04:05.999999999Z07:00"

// RequestCancellation durably records cancellation intent before any signal or
// guest request is attempted. Terminal operations remain unchanged.
func (store *Store) RequestCancellation(ctx context.Context, operationID string) (Operation, error) {
	now := store.timestamp()
	if _, err := store.db.ExecContext(ctx, `
UPDATE operations SET cancellation_requested = 1, updated_at = ?
WHERE operation_id = ? AND state IN ('accepted','running')`, now, operationID); err != nil {
		return Operation{}, fmt.Errorf("persist cancellation intent: %w", err)
	}
	return store.GetOperation(ctx, operationID)
}

// SetOperationPaths records bounded managed spool and result paths before use.
func (store *Store) SetOperationPaths(ctx context.Context, operationID, resultPath, stdoutPath, stderrPath string) (Operation, error) {
	for _, value := range []string{resultPath, stdoutPath, stderrPath} {
		if len(value) > 4096 {
			return Operation{}, fmt.Errorf("operation path exceeds bound")
		}
	}
	result, err := store.db.ExecContext(ctx, `
UPDATE operations SET result_path = ?, stdout_path = ?, stderr_path = ?, updated_at = ?
WHERE operation_id = ? AND state IN ('accepted','running')`, resultPath, stdoutPath, stderrPath, store.timestamp(), operationID)
	if err != nil {
		return Operation{}, fmt.Errorf("persist operation paths: %w", err)
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return Operation{}, fmt.Errorf("read operation path update result: %w", err)
	}
	if rows == 0 {
		operation, getErr := store.GetOperation(ctx, operationID)
		if getErr != nil {
			return Operation{}, getErr
		}
		if contracts.OperationState(operation.State).Terminal() {
			return Operation{}, ErrTerminalOperation
		}
	}
	return store.GetOperation(ctx, operationID)
}

// AdvanceStreamCursors persists monotonic host-observed stream positions.
func (store *Store) AdvanceStreamCursors(ctx context.Context, operationID string, stdoutCursor, stderrCursor int64) (Operation, error) {
	if stdoutCursor < 0 || stderrCursor < 0 {
		return Operation{}, fmt.Errorf("stream cursors must be nonnegative")
	}
	if _, err := store.db.ExecContext(ctx, `
UPDATE operations SET
    stdout_cursor = CASE WHEN stdout_cursor < ? THEN ? ELSE stdout_cursor END,
    stderr_cursor = CASE WHEN stderr_cursor < ? THEN ? ELSE stderr_cursor END,
    updated_at = ?
WHERE operation_id = ?`, stdoutCursor, stdoutCursor, stderrCursor, stderrCursor, store.timestamp(), operationID); err != nil {
		return Operation{}, fmt.Errorf("persist stream cursors: %w", err)
	}
	return store.GetOperation(ctx, operationID)
}

func validateOperationRequest(request OperationRequest) error {
	if request.OperationID == "" || len(request.OperationID) > 128 {
		return fmt.Errorf("valid operation ID is required")
	}
	if !operationPattern.MatchString(request.OperationName) {
		return fmt.Errorf("invalid operation name %q", request.OperationName)
	}
	if request.OperationVersion < 1 {
		return fmt.Errorf("operation version must be positive")
	}
	if request.IdempotencyKey == "" || len(request.IdempotencyKey) > 256 {
		return fmt.Errorf("idempotency key is required and bounded")
	}
	if !digestPattern.MatchString(request.RequestDigest) {
		return fmt.Errorf("request digest must be lowercase SHA-256")
	}
	if len(request.MachineID) > 128 {
		return fmt.Errorf("machine ID exceeds bound")
	}
	return nil
}

func sameOperationRequest(existing Operation, request OperationRequest) bool {
	return existing.OperationName == request.OperationName &&
		existing.OperationVersion == request.OperationVersion &&
		existing.IdempotencyKey == request.IdempotencyKey &&
		existing.RequestDigest == request.RequestDigest &&
		existing.MachineID == request.MachineID
}

func scanOperation(row rowScanner) (Operation, error) {
	var operation Operation
	var cancelled int
	var created, updated string
	var started, finished sql.NullString
	if err := row.Scan(
		&operation.OperationID, &operation.OperationName, &operation.OperationVersion,
		&operation.IdempotencyKey, &operation.RequestDigest, &operation.MachineID,
		&operation.State, &cancelled, &operation.ResultPath, &operation.ErrorCode,
		&operation.ErrorMessage, &operation.StdoutPath, &operation.StderrPath,
		&operation.StdoutCursor, &operation.StderrCursor, &created, &updated,
		&started, &finished,
	); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return Operation{}, ErrNotFound
		}
		return Operation{}, fmt.Errorf("scan operation truth: %w", err)
	}
	operation.CancellationRequested = cancelled == 1
	var err error
	if operation.CreatedAt, err = parseTime(created); err != nil {
		return Operation{}, err
	}
	if operation.UpdatedAt, err = parseTime(updated); err != nil {
		return Operation{}, err
	}
	if operation.StartedAt, err = parseNullableTime(started); err != nil {
		return Operation{}, err
	}
	if operation.FinishedAt, err = parseNullableTime(finished); err != nil {
		return Operation{}, err
	}
	if strings.TrimSpace(operation.OperationName) == "" {
		return Operation{}, fmt.Errorf("durable operation has empty name")
	}
	return operation, nil
}
