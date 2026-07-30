// Package atomicfile provides the single durable authoritative-file writer used
// by EHJINT. It rejects lexical and symbolic-link escapes, writes and fsyncs a
// complete temporary file, atomically renames it, fsyncs the parent directory,
// and reopens the result for verification.
package atomicfile

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"syscall"

	"github.com/StealthEyeLLC/ehjint/internal/layout"
)

// Owner is the exact expected owner of an authoritative file.
type Owner struct {
	UID int
	GID int
}

// Verifier validates complete bytes before and after installation.
type Verifier func([]byte) error

type hooks struct {
	beforeRename func(string) error
}

// Write installs data at destination under root.
func Write(root, destination string, data []byte, mode fs.FileMode, owner Owner) error {
	return write(root, destination, data, mode, owner, nil, hooks{})
}

// WriteVerified installs data and invokes verifier before mutation and after
// reopening the installed file.
func WriteVerified(root, destination string, data []byte, mode fs.FileMode, owner Owner, verifier Verifier) error {
	return write(root, destination, data, mode, owner, verifier, hooks{})
}

// WriteJSON marshals exactly one strict authoritative JSON document and
// installs it through the common writer. The caller verifier may enforce the
// destination-specific strict schema.
func WriteJSON(root, destination string, value any, mode fs.FileMode, owner Owner, verifier Verifier) error {
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal authoritative JSON: %w", err)
	}
	data = append(data, '\n')
	combined := func(candidate []byte) error {
		if err := VerifyJSON(candidate, nil); err != nil {
			return err
		}
		if verifier != nil {
			return verifier(candidate)
		}
		return nil
	}
	return write(root, destination, data, mode, owner, combined, hooks{})
}

// VerifyJSON rejects empty, partial, concatenated, and trailing JSON. When
// target is non-nil, unknown object fields are rejected while decoding it.
func VerifyJSON(data []byte, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if target == nil {
		var value any
		target = &value
	}
	if err := decoder.Decode(target); err != nil {
		return fmt.Errorf("decode strict JSON: %w", err)
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		if err == nil {
			return fmt.Errorf("strict JSON contains a second value")
		}
		return fmt.Errorf("strict JSON trailing data: %w", err)
	}
	return nil
}

func write(root, destination string, data []byte, mode fs.FileMode, owner Owner, verifier Verifier, testHooks hooks) error {
	if len(data) == 0 {
		return fmt.Errorf("authoritative file content is empty")
	}
	if mode.Perm() == 0 || mode.Perm()&0o002 != 0 || mode&^fs.ModePerm != 0 {
		return fmt.Errorf("unsafe authoritative file mode %04o", mode)
	}
	if owner.UID < 0 || owner.GID < 0 {
		return fmt.Errorf("authoritative file owner must be explicit")
	}
	cleanRoot := filepath.Clean(root)
	cleanDestination := filepath.Clean(destination)
	if !filepath.IsAbs(cleanRoot) || !filepath.IsAbs(cleanDestination) || !layout.Within(cleanRoot, cleanDestination) {
		return fmt.Errorf("authoritative destination escapes managed root")
	}
	parent := filepath.Dir(cleanDestination)
	if err := validateParentChain(cleanRoot, parent); err != nil {
		return err
	}
	if err := validateExisting(cleanDestination, owner); err != nil {
		return err
	}
	if verifier != nil {
		if err := verifier(data); err != nil {
			return fmt.Errorf("verify authoritative content before write: %w", err)
		}
	}

	temporary, err := os.CreateTemp(parent, ".ehjint-atomic-")
	if err != nil {
		return fmt.Errorf("create authoritative temporary file: %w", err)
	}
	temporaryName := temporary.Name()
	cleanup := func() {
		_ = temporary.Close()
		_ = os.Remove(temporaryName)
	}
	defer cleanup()
	if err := temporary.Chmod(0o600); err != nil {
		return fmt.Errorf("restrict authoritative temporary file: %w", err)
	}
	if err := temporary.Chown(owner.UID, owner.GID); err != nil {
		return fmt.Errorf("set authoritative file owner: %w", err)
	}
	if _, err := temporary.Write(data); err != nil {
		return fmt.Errorf("write authoritative temporary file: %w", err)
	}
	if err := temporary.Sync(); err != nil {
		return fmt.Errorf("fsync authoritative temporary file: %w", err)
	}
	if err := temporary.Chmod(mode.Perm()); err != nil {
		return fmt.Errorf("set authoritative file mode: %w", err)
	}
	if err := temporary.Sync(); err != nil {
		return fmt.Errorf("fsync authoritative metadata: %w", err)
	}
	if err := temporary.Close(); err != nil {
		return fmt.Errorf("close authoritative temporary file: %w", err)
	}
	if testHooks.beforeRename != nil {
		if err := testHooks.beforeRename(temporaryName); err != nil {
			return err
		}
	}
	if err := validateParentChain(cleanRoot, parent); err != nil {
		return fmt.Errorf("revalidate authoritative parent: %w", err)
	}
	if err := validateExisting(cleanDestination, owner); err != nil {
		return fmt.Errorf("revalidate authoritative destination: %w", err)
	}
	if err := os.Rename(temporaryName, cleanDestination); err != nil {
		return fmt.Errorf("atomically replace authoritative file: %w", err)
	}
	if err := syncDirectory(parent); err != nil {
		return err
	}
	if err := verifyInstalled(cleanDestination, data, mode, owner, verifier); err != nil {
		return err
	}
	return nil
}

func validateParentChain(root, parent string) error {
	rootInfo, err := os.Lstat(root)
	if err != nil {
		return fmt.Errorf("inspect managed root: %w", err)
	}
	if rootInfo.Mode()&os.ModeSymlink != 0 || !rootInfo.IsDir() {
		return fmt.Errorf("managed root is not a real directory")
	}
	if rootInfo.Mode().Perm()&0o002 != 0 {
		return fmt.Errorf("managed root is world-writable")
	}
	relative, err := filepath.Rel(root, parent)
	if err != nil || relative == ".." || filepath.IsAbs(relative) {
		return fmt.Errorf("authoritative parent escapes managed root")
	}
	current := root
	if relative != "." {
		for _, component := range splitPath(relative) {
			current = filepath.Join(current, component)
			info, err := os.Lstat(current)
			if err != nil {
				return fmt.Errorf("inspect authoritative parent component %s: %w", current, err)
			}
			if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
				return fmt.Errorf("authoritative parent component is not a real directory: %s", current)
			}
			if info.Mode().Perm()&0o002 != 0 {
				return fmt.Errorf("authoritative parent component is world-writable: %s", current)
			}
		}
	}
	resolvedRoot, err := filepath.EvalSymlinks(root)
	if err != nil {
		return fmt.Errorf("resolve managed root: %w", err)
	}
	resolvedParent, err := filepath.EvalSymlinks(parent)
	if err != nil {
		return fmt.Errorf("resolve authoritative parent: %w", err)
	}
	if resolvedParent != resolvedRoot && !layout.Within(resolvedRoot, resolvedParent) {
		return fmt.Errorf("authoritative parent resolves outside managed root")
	}
	return nil
}

func splitPath(path string) []string {
	result := make([]string, 0)
	for path != "." && path != string(filepath.Separator) && path != "" {
		directory, file := filepath.Split(path)
		if file != "" {
			result = append([]string{file}, result...)
		}
		path = filepath.Clean(directory)
	}
	return result
}

func validateExisting(destination string, owner Owner) error {
	info, err := os.Lstat(destination)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("inspect authoritative destination: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return fmt.Errorf("authoritative destination is not a regular file")
	}
	uid, gid, err := fileOwner(info)
	if err != nil {
		return err
	}
	if uid != owner.UID || gid != owner.GID {
		return fmt.Errorf("authoritative destination owner mismatch: %d:%d", uid, gid)
	}
	return nil
}

func verifyInstalled(destination string, expected []byte, mode fs.FileMode, owner Owner, verifier Verifier) error {
	info, err := os.Lstat(destination)
	if err != nil {
		return fmt.Errorf("reopen authoritative file metadata: %w", err)
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("installed authoritative path is not a regular file")
	}
	if info.Mode().Perm() != mode.Perm() {
		return fmt.Errorf("installed authoritative file mode mismatch: %04o", info.Mode().Perm())
	}
	uid, gid, err := fileOwner(info)
	if err != nil {
		return err
	}
	if uid != owner.UID || gid != owner.GID {
		return fmt.Errorf("installed authoritative file owner mismatch: %d:%d", uid, gid)
	}
	actual, err := os.ReadFile(destination)
	if err != nil {
		return fmt.Errorf("reopen authoritative file: %w", err)
	}
	if !bytes.Equal(actual, expected) {
		return fmt.Errorf("installed authoritative file bytes differ from complete input")
	}
	if verifier != nil {
		if err := verifier(actual); err != nil {
			return fmt.Errorf("verify installed authoritative content: %w", err)
		}
	}
	return nil
}

func fileOwner(info fs.FileInfo) (int, int, error) {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, 0, fmt.Errorf("authoritative file ownership is unavailable")
	}
	return int(stat.Uid), int(stat.Gid), nil
}

func syncDirectory(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("open authoritative parent for fsync: %w", err)
	}
	defer directory.Close()
	if err := directory.Sync(); err != nil {
		return fmt.Errorf("fsync authoritative parent directory: %w", err)
	}
	return nil
}
