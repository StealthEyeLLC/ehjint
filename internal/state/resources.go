package state

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
)

var resourceKinds = map[string]bool{
	"directory": true, "file": true, "symlink": true, "socket": true, "process": true,
	"machine_identity": true, "overlay": true, "seed": true, "certificate": true, "release_reference": true,
}

// RecordResource persists exact cleanup ownership. Repeating the exact record
// is idempotent; a conflicting claim is rejected.
func (store *Store) RecordResource(ctx context.Context, resource OwnedResource) (OwnedResource, bool, error) {
	if !resourceKinds[resource.Kind] || resource.Path == "" || len(resource.Path) > 4096 || len(resource.Identity) > 512 {
		return OwnedResource{}, false, fmt.Errorf("invalid or unbounded owned resource")
	}
	if resource.Digest != "" && !digestPattern.MatchString(resource.Digest) {
		return OwnedResource{}, false, fmt.Errorf("owned resource digest must be lowercase SHA-256")
	}
	transaction, err := store.db.BeginTx(ctx, nil)
	if err != nil {
		return OwnedResource{}, false, fmt.Errorf("begin resource record: %w", err)
	}
	defer transaction.Rollback()
	existing, err := scanResource(transaction.QueryRowContext(ctx, `
SELECT resource_id, COALESCE(machine_id, ''), kind, path, identity, digest, uid, gid, created_at
FROM owned_resources WHERE kind = ? AND path = ?`, resource.Kind, resource.Path))
	if err == nil {
		if !sameResource(existing, resource) {
			return OwnedResource{}, false, fmt.Errorf("owned resource conflicts with an existing claim")
		}
		if err := transaction.Commit(); err != nil {
			return OwnedResource{}, false, fmt.Errorf("commit resource replay: %w", err)
		}
		return existing, true, nil
	}
	if !errors.Is(err, ErrNotFound) {
		return OwnedResource{}, false, err
	}
	var machineID any
	if resource.MachineID != "" {
		machineID = resource.MachineID
	}
	result, err := transaction.ExecContext(ctx, `
INSERT INTO owned_resources(machine_id, kind, path, identity, digest, uid, gid, created_at)
VALUES(?, ?, ?, ?, ?, ?, ?, ?)`, machineID, resource.Kind, resource.Path, resource.Identity,
		resource.Digest, nullableInt(resource.UID), nullableInt(resource.GID), store.timestamp())
	if err != nil {
		return OwnedResource{}, false, fmt.Errorf("persist owned resource: %w", err)
	}
	id, err := result.LastInsertId()
	if err != nil {
		return OwnedResource{}, false, fmt.Errorf("read owned resource identity: %w", err)
	}
	created, err := scanResource(transaction.QueryRowContext(ctx, `
SELECT resource_id, COALESCE(machine_id, ''), kind, path, identity, digest, uid, gid, created_at
FROM owned_resources WHERE resource_id = ?`, id))
	if err != nil {
		return OwnedResource{}, false, err
	}
	if err := transaction.Commit(); err != nil {
		return OwnedResource{}, false, fmt.Errorf("commit owned resource: %w", err)
	}
	return created, false, nil
}

// ListResources returns stable cleanup order, newest claims first.
func (store *Store) ListResources(ctx context.Context, machineID string) ([]OwnedResource, error) {
	rows, err := store.db.QueryContext(ctx, `
SELECT resource_id, COALESCE(machine_id, ''), kind, path, identity, digest, uid, gid, created_at
FROM owned_resources WHERE machine_id = ? ORDER BY resource_id DESC`, machineID)
	if err != nil {
		return nil, fmt.Errorf("list owned resources: %w", err)
	}
	defer rows.Close()
	var result []OwnedResource
	for rows.Next() {
		resource, scanErr := scanResource(rows)
		if scanErr != nil {
			return nil, scanErr
		}
		result = append(result, resource)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate owned resources: %w", err)
	}
	return result, nil
}

// ForgetResource removes a cleanup claim only after cleanup has been verified.
func (store *Store) ForgetResource(ctx context.Context, resourceID int64) error {
	result, err := store.db.ExecContext(ctx, `DELETE FROM owned_resources WHERE resource_id = ?`, resourceID)
	if err != nil {
		return fmt.Errorf("forget owned resource: %w", err)
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("read resource deletion result: %w", err)
	}
	if rows != 1 {
		return ErrNotFound
	}
	return nil
}

// RecordCompatibility records one explicit compatibility family version and
// source digest. It never infers compatibility from success.
func (store *Store) RecordCompatibility(ctx context.Context, name string, version int, digest string) error {
	if name == "" || len(name) > 128 || version < 1 || !digestPattern.MatchString(digest) {
		return fmt.Errorf("invalid compatibility record")
	}
	_, err := store.db.ExecContext(ctx, `
INSERT INTO compatibility_records(name, version, digest, updated_at) VALUES(?, ?, ?, ?)
ON CONFLICT(name) DO UPDATE SET version = excluded.version, digest = excluded.digest, updated_at = excluded.updated_at`,
		name, version, digest, store.timestamp())
	if err != nil {
		return fmt.Errorf("persist compatibility record: %w", err)
	}
	return nil
}

// Compatibility returns explicit compatibility truth.
func (store *Store) Compatibility(ctx context.Context, name string) (int, string, error) {
	var version int
	var digest string
	if err := store.db.QueryRowContext(ctx, `SELECT version, digest FROM compatibility_records WHERE name = ?`, name).Scan(&version, &digest); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return 0, "", ErrNotFound
		}
		return 0, "", fmt.Errorf("read compatibility record: %w", err)
	}
	return version, digest, nil
}

func scanResource(row rowScanner) (OwnedResource, error) {
	var resource OwnedResource
	var uid, gid sql.NullInt64
	var created string
	if err := row.Scan(&resource.ResourceID, &resource.MachineID, &resource.Kind, &resource.Path,
		&resource.Identity, &resource.Digest, &uid, &gid, &created); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return OwnedResource{}, ErrNotFound
		}
		return OwnedResource{}, fmt.Errorf("scan owned resource: %w", err)
	}
	if uid.Valid {
		value := int(uid.Int64)
		resource.UID = &value
	}
	if gid.Valid {
		value := int(gid.Int64)
		resource.GID = &value
	}
	var err error
	resource.CreatedAt, err = parseTime(created)
	if err != nil {
		return OwnedResource{}, err
	}
	return resource, nil
}

func nullableInt(value *int) any {
	if value == nil {
		return nil
	}
	return *value
}

func sameResource(left, right OwnedResource) bool {
	return left.MachineID == right.MachineID && left.Kind == right.Kind && left.Path == right.Path &&
		left.Identity == right.Identity && left.Digest == right.Digest && sameInt(left.UID, right.UID) && sameInt(left.GID, right.GID)
}

func sameInt(left, right *int) bool {
	if left == nil || right == nil {
		return left == right
	}
	return *left == *right
}
