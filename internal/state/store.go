// Package state owns EHJINT's single SQLite durable metadata authority.
package state

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

const (
	// SchemaVersion is the compact controller database schema implemented by
	// Mission 2.
	SchemaVersion = 1
	// BusyTimeout is deliberately bounded: callers receive explicit contention
	// truth rather than waiting forever.
	BusyTimeout = 5 * time.Second
)

var (
	ErrNotFound            = errors.New("durable record not found")
	ErrIdempotencyConflict = errors.New("idempotency key conflicts with a different request")
	ErrTerminalOperation   = errors.New("terminal operation is immutable")
	ErrMachineConflict     = errors.New("machine immutable configuration conflicts")
)

// Store contains no authoritative in-memory maps. Reopening the database is
// sufficient to recover all durable controller truth.
type Store struct {
	db   *sql.DB
	path string
	now  func() time.Time
}

// Pragmas is the verified runtime SQLite contract.
type Pragmas struct {
	JournalMode string
	ForeignKeys bool
	Synchronous int
	BusyTimeout int
}

// Open validates the database path, opens SQLite with the exact Mission 2
// pragmas, applies compact in-code migrations, and refuses corruption.
func Open(ctx context.Context, path string) (*Store, error) {
	clean := filepath.Clean(path)
	if !filepath.IsAbs(clean) {
		return nil, fmt.Errorf("controller database path must be absolute")
	}
	parent := filepath.Dir(clean)
	parentInfo, err := os.Lstat(parent)
	if err != nil {
		return nil, fmt.Errorf("inspect controller database parent: %w", err)
	}
	if parentInfo.Mode()&os.ModeSymlink != 0 || !parentInfo.IsDir() {
		return nil, fmt.Errorf("controller database parent is not a real directory")
	}
	if parentInfo.Mode().Perm()&0o002 != 0 {
		return nil, fmt.Errorf("controller database parent is world-writable")
	}
	if info, statErr := os.Lstat(clean); statErr == nil {
		if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
			return nil, fmt.Errorf("controller database is not a regular file")
		}
		if info.Mode().Perm()&0o077 != 0 {
			return nil, fmt.Errorf("controller database permissions are not private: %04o", info.Mode().Perm())
		}
	} else if !errors.Is(statErr, os.ErrNotExist) {
		return nil, fmt.Errorf("inspect controller database: %w", statErr)
	} else {
		file, createErr := os.OpenFile(clean, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0o600)
		if createErr != nil {
			return nil, fmt.Errorf("create controller database: %w", createErr)
		}
		if closeErr := file.Close(); closeErr != nil {
			return nil, fmt.Errorf("close new controller database: %w", closeErr)
		}
	}

	fileURL := (&url.URL{Scheme: "file", Path: clean}).String()
	dsn := fileURL + "?_busy_timeout=5000&_foreign_keys=on&_journal_mode=WAL&_synchronous=FULL&_txlock=immediate"
	database, err := sql.Open("sqlite3", dsn)
	if err != nil {
		return nil, fmt.Errorf("open controller database: %w", err)
	}
	// One connection keeps connection-scoped pragmas exact while database/sql
	// still safely serializes concurrent callers. WAL remains valuable for
	// crash recovery and external read-only inspection.
	database.SetMaxOpenConns(1)
	database.SetMaxIdleConns(1)
	store := &Store{db: database, path: clean, now: func() time.Time { return time.Now().UTC() }}
	closeOnError := func(cause error) (*Store, error) {
		_ = database.Close()
		return nil, cause
	}
	if err := database.PingContext(ctx); err != nil {
		return closeOnError(fmt.Errorf("ping controller database: %w", err))
	}
	if err := store.applyPragmas(ctx); err != nil {
		return closeOnError(err)
	}
	if err := store.migrate(ctx); err != nil {
		return closeOnError(err)
	}
	if err := store.integrityCheck(ctx); err != nil {
		return closeOnError(err)
	}
	if _, err := store.VerifyPragmas(ctx); err != nil {
		return closeOnError(err)
	}
	return store, nil
}

// Close closes the durable authority.
func (store *Store) Close() error { return store.db.Close() }

// Path returns the exact database path without exposing the SQL handle.
func (store *Store) Path() string { return store.path }

// Schema returns the applied schema version.
func (store *Store) Schema(ctx context.Context) (int, error) {
	var version int
	if err := store.db.QueryRowContext(ctx, `SELECT COALESCE(MAX(version), 0) FROM schema_migrations`).Scan(&version); err != nil {
		return 0, fmt.Errorf("read controller schema version: %w", err)
	}
	return version, nil
}

// VerifyPragmas reads and verifies every required pragma.
func (store *Store) VerifyPragmas(ctx context.Context) (Pragmas, error) {
	var result Pragmas
	var foreignKeys int
	if err := store.db.QueryRowContext(ctx, `PRAGMA journal_mode`).Scan(&result.JournalMode); err != nil {
		return Pragmas{}, fmt.Errorf("read journal_mode: %w", err)
	}
	if err := store.db.QueryRowContext(ctx, `PRAGMA foreign_keys`).Scan(&foreignKeys); err != nil {
		return Pragmas{}, fmt.Errorf("read foreign_keys: %w", err)
	}
	if err := store.db.QueryRowContext(ctx, `PRAGMA synchronous`).Scan(&result.Synchronous); err != nil {
		return Pragmas{}, fmt.Errorf("read synchronous: %w", err)
	}
	if err := store.db.QueryRowContext(ctx, `PRAGMA busy_timeout`).Scan(&result.BusyTimeout); err != nil {
		return Pragmas{}, fmt.Errorf("read busy_timeout: %w", err)
	}
	result.JournalMode = strings.ToLower(result.JournalMode)
	result.ForeignKeys = foreignKeys == 1
	if result.JournalMode != "wal" {
		return Pragmas{}, fmt.Errorf("journal_mode is %q, expected WAL", result.JournalMode)
	}
	if !result.ForeignKeys {
		return Pragmas{}, fmt.Errorf("foreign_keys is disabled")
	}
	if result.Synchronous != 2 {
		return Pragmas{}, fmt.Errorf("synchronous is %d, expected FULL (2)", result.Synchronous)
	}
	if result.BusyTimeout != int(BusyTimeout/time.Millisecond) {
		return Pragmas{}, fmt.Errorf("busy_timeout is %d, expected %d", result.BusyTimeout, BusyTimeout/time.Millisecond)
	}
	return result, nil
}

func (store *Store) applyPragmas(ctx context.Context) error {
	statements := []string{
		`PRAGMA journal_mode=WAL`,
		`PRAGMA foreign_keys=ON`,
		`PRAGMA synchronous=FULL`,
		`PRAGMA busy_timeout=5000`,
	}
	for _, statement := range statements {
		if _, err := store.db.ExecContext(ctx, statement); err != nil {
			return fmt.Errorf("apply %s: %w", statement, err)
		}
	}
	return nil
}

func (store *Store) integrityCheck(ctx context.Context) error {
	var result string
	if err := store.db.QueryRowContext(ctx, `PRAGMA integrity_check`).Scan(&result); err != nil {
		return fmt.Errorf("run controller database integrity check: %w", err)
	}
	if result != "ok" {
		return fmt.Errorf("controller database integrity check failed: %s", result)
	}
	return nil
}

func (store *Store) migrate(ctx context.Context) error {
	if _, err := store.db.ExecContext(ctx, `
CREATE TABLE IF NOT EXISTS schema_migrations (
    version INTEGER PRIMARY KEY,
    applied_at TEXT NOT NULL
)`); err != nil {
		return fmt.Errorf("create schema migration authority: %w", err)
	}
	version, err := store.Schema(ctx)
	if err != nil {
		return err
	}
	if version > SchemaVersion {
		return fmt.Errorf("controller database schema %d is newer than supported schema %d", version, SchemaVersion)
	}
	if version == SchemaVersion {
		return nil
	}
	transaction, err := store.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin controller migration: %w", err)
	}
	defer transaction.Rollback()
	if version == 0 {
		if _, err := transaction.ExecContext(ctx, migration1); err != nil {
			return fmt.Errorf("apply controller migration 1: %w", err)
		}
		if _, err := transaction.ExecContext(ctx, `INSERT INTO schema_migrations(version, applied_at) VALUES(1, ?)`, store.timestamp()); err != nil {
			return fmt.Errorf("record controller migration 1: %w", err)
		}
		version = 1
	}
	if version != SchemaVersion {
		return fmt.Errorf("no migration path from schema %d to %d", version, SchemaVersion)
	}
	if err := transaction.Commit(); err != nil {
		return fmt.Errorf("commit controller migration: %w", err)
	}
	return nil
}

func (store *Store) timestamp() string { return store.now().UTC().Format(time.RFC3339Nano) }

const migration1 = `
CREATE TABLE machines (
    machine_id TEXT PRIMARY KEY,
    stable_name TEXT NOT NULL UNIQUE,
    desired_state TEXT NOT NULL CHECK(desired_state IN ('running','stopped','absent')),
    observed_state TEXT NOT NULL CHECK(observed_state IN ('absent','preparing','starting','running','stopping','stopped','removing','degraded','unknown')),
    manifest_path TEXT NOT NULL,
    manifest_digest TEXT NOT NULL CHECK(length(manifest_digest) = 64),
    creating_release TEXT NOT NULL,
    vmm_version TEXT NOT NULL,
    vmm_digest TEXT NOT NULL CHECK(length(vmm_digest) = 64),
    guest_image_digest TEXT NOT NULL CHECK(length(guest_image_digest) = 64),
    firmware_digest TEXT NOT NULL CHECK(length(firmware_digest) = 64),
    overlay_identity TEXT NOT NULL,
    vsock_cid INTEGER NOT NULL UNIQUE CHECK(vsock_cid >= 3),
    agent_port INTEGER NOT NULL CHECK(agent_port > 0 AND agent_port <= 4294967295),
    vmm_identity TEXT NOT NULL UNIQUE,
    vmm_uid INTEGER NOT NULL UNIQUE CHECK(vmm_uid > 0),
    vmm_gid INTEGER NOT NULL UNIQUE CHECK(vmm_gid > 0),
    vmm_pid INTEGER,
    process_start_identity TEXT NOT NULL DEFAULT '',
    api_socket TEXT NOT NULL,
    vsock_socket TEXT NOT NULL,
    guest_boot_id TEXT NOT NULL DEFAULT '',
    readiness_state TEXT NOT NULL DEFAULT 'not_ready',
    last_failure TEXT NOT NULL DEFAULT '',
    generation INTEGER NOT NULL DEFAULT 1 CHECK(generation > 0),
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE operations (
    operation_id TEXT PRIMARY KEY,
    operation_name TEXT NOT NULL,
    operation_version INTEGER NOT NULL CHECK(operation_version > 0),
    idempotency_key TEXT NOT NULL UNIQUE,
    request_digest TEXT NOT NULL CHECK(length(request_digest) = 64),
    machine_id TEXT,
    state TEXT NOT NULL CHECK(state IN ('accepted','running','succeeded','failed','cancelled')),
    cancellation_requested INTEGER NOT NULL DEFAULT 0 CHECK(cancellation_requested IN (0,1)),
    result_path TEXT NOT NULL DEFAULT '',
    error_code TEXT NOT NULL DEFAULT '',
    error_message TEXT NOT NULL DEFAULT '',
    stdout_path TEXT NOT NULL DEFAULT '',
    stderr_path TEXT NOT NULL DEFAULT '',
    stdout_cursor INTEGER NOT NULL DEFAULT 0 CHECK(stdout_cursor >= 0),
    stderr_cursor INTEGER NOT NULL DEFAULT 0 CHECK(stderr_cursor >= 0),
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    started_at TEXT,
    finished_at TEXT
);
CREATE INDEX operations_state_index ON operations(state);
CREATE INDEX operations_machine_index ON operations(machine_id);

CREATE TABLE owned_resources (
    resource_id INTEGER PRIMARY KEY AUTOINCREMENT,
    machine_id TEXT,
    kind TEXT NOT NULL CHECK(kind IN ('directory','file','symlink','socket','process','machine_identity','overlay','seed','certificate','release_reference')),
    path TEXT NOT NULL,
    identity TEXT NOT NULL DEFAULT '',
    digest TEXT NOT NULL DEFAULT '',
    uid INTEGER,
    gid INTEGER,
    created_at TEXT NOT NULL,
    UNIQUE(kind, path),
    FOREIGN KEY(machine_id) REFERENCES machines(machine_id) ON DELETE RESTRICT
);
CREATE INDEX owned_resources_machine_index ON owned_resources(machine_id);

CREATE TABLE compatibility_records (
    name TEXT PRIMARY KEY,
    version INTEGER NOT NULL CHECK(version > 0),
    digest TEXT NOT NULL CHECK(length(digest) = 64),
    updated_at TEXT NOT NULL
);
`
