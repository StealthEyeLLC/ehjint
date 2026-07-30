package atomicfile

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func currentOwner() Owner { return Owner{UID: os.Getuid(), GID: os.Getgid()} }

func TestWriteAndJSONVerification(t *testing.T) {
	root := t.TempDir()
	directory := filepath.Join(root, "state")
	if err := os.Mkdir(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, "record.json")
	type record struct {
		Name string `json:"name"`
	}
	verify := func(data []byte) error {
		var value record
		return VerifyJSON(data, &value)
	}
	if err := WriteJSON(root, path, record{Name: "exact"}, 0o600, currentOwner(), verify); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(data, []byte("{\n  \"name\": \"exact\"\n}\n")) {
		t.Fatalf("unexpected bytes: %q", data)
	}
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("unexpected mode or stat error: %v %v", info, err)
	}
}

func TestInterruptionBeforeRenamePreservesOriginal(t *testing.T) {
	root := t.TempDir()
	directory := filepath.Join(root, "state")
	if err := os.Mkdir(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, "record")
	if err := os.WriteFile(path, []byte("original"), 0o600); err != nil {
		t.Fatal(err)
	}
	interrupted := errors.New("injected interruption")
	err := write(root, path, []byte("replacement"), 0o600, currentOwner(), nil, hooks{
		beforeRename: func(string) error { return interrupted },
	})
	if !errors.Is(err, interrupted) {
		t.Fatalf("got %v", err)
	}
	data, err := os.ReadFile(path)
	if err != nil || string(data) != "original" {
		t.Fatalf("partial replacement escaped: %q %v", data, err)
	}
	matches, err := filepath.Glob(filepath.Join(directory, ".ehjint-atomic-*"))
	if err != nil || len(matches) != 0 {
		t.Fatalf("temporary file escaped: %v %v", matches, err)
	}
}

func TestRejectsSymlinksWrongOwnerAndWorldWritableParents(t *testing.T) {
	root := t.TempDir()
	directory := filepath.Join(root, "state")
	if err := os.Mkdir(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(directory, "target")
	if err := os.WriteFile(target, []byte("target"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(directory, "link")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if err := Write(root, link, []byte("bad"), 0o600, currentOwner()); err == nil {
		t.Fatal("destination symlink accepted")
	}
	outside := t.TempDir()
	parentLink := filepath.Join(root, "linked")
	if err := os.Symlink(outside, parentLink); err != nil {
		t.Fatal(err)
	}
	if err := Write(root, filepath.Join(parentLink, "file"), []byte("bad"), 0o600, currentOwner()); err == nil {
		t.Fatal("parent symlink accepted")
	}
	wrong := Owner{UID: os.Getuid() + 1, GID: os.Getgid()}
	if err := Write(root, target, []byte("bad"), 0o600, wrong); err == nil {
		t.Fatal("wrong existing owner accepted")
	}
	world := filepath.Join(root, "world")
	if err := os.Mkdir(world, 0o777); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(world, 0o777); err != nil {
		t.Fatal(err)
	}
	if err := Write(root, filepath.Join(world, "file"), []byte("bad"), 0o600, currentOwner()); err == nil {
		t.Fatal("world-writable parent accepted")
	}
}

func TestVerifyJSONRejectsPartialUnknownAndConcatenated(t *testing.T) {
	type strict struct {
		Name string `json:"name"`
	}
	for _, data := range [][]byte{
		[]byte(`{"name":`),
		[]byte("{\"name\":\"one\"}\n{\"name\":\"two\"}"),
		[]byte(`{"name":"one","extra":true}`),
	} {
		var value strict
		if err := VerifyJSON(data, &value); err == nil {
			t.Fatalf("invalid strict JSON accepted: %q", data)
		}
	}
}
