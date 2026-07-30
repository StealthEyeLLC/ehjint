package qcow2

import (
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"syscall"
	"testing"

	"github.com/StealthEyeLLC/ehjint/internal/atomicfile"
)

func testSpec(root string) Spec {
	return Spec{VirtualSize: 32 * 1024 * 1024 * 1024, BackingFile: filepath.Join(root, "images", "base.img"), BackingFormat: "qcow2"}
}

func TestBuildIsDeterministicAndStrict(t *testing.T) {
	root := t.TempDir()
	first, metadata, err := Build(testSpec(root))
	if err != nil {
		t.Fatal(err)
	}
	second, secondMetadata, err := Build(testSpec(root))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first, second) || metadata.SHA256 != secondMetadata.SHA256 {
		t.Fatal("QCOW2 construction is not deterministic")
	}
	if metadata.Version != 3 || metadata.BackingFormat != "qcow2" || metadata.VirtualSize != 32*1024*1024*1024 || metadata.L1Size == 0 {
		t.Fatalf("unexpected metadata: %+v", metadata)
	}
}

func TestInspectRejectsCorruptionAndImplicitFormat(t *testing.T) {
	image, _, err := Build(testSpec(t.TempDir()))
	if err != nil {
		t.Fatal(err)
	}
	cases := map[string]func([]byte){
		"magic":            func(data []byte) { data[0] = 0 },
		"version":          func(data []byte) { data[7] = 2 },
		"format extension": func(data []byte) { data[104] = 0 },
		"L1 allocation":    func(data []byte) { data[l1TableOffset] = 1 },
		"refcount":         func(data []byte) { data[refcountBlockOffset+1] = 2 },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			candidate := append([]byte(nil), image...)
			mutate(candidate)
			if _, err := Inspect(candidate); err == nil {
				t.Fatal("corruption accepted")
			}
		})
	}
	bad := testSpec(t.TempDir())
	bad.BackingFormat = ""
	if _, _, err := Build(bad); err == nil {
		t.Fatal("implicit backing format accepted")
	}
}

func TestWriteSparseIsAtomicIdempotentAndSparse(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("sparse block accounting is Linux-specific")
	}
	root := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, "machines"), 0o700); err != nil {
		t.Fatal(err)
	}
	destination := filepath.Join(root, "machines", "root.qcow2")
	owner := atomicfile.Owner{UID: os.Getuid(), GID: os.Getgid()}
	metadata, err := WriteSparse(root, destination, testSpec(root), 0o600, owner)
	if err != nil {
		t.Fatal(err)
	}
	second, err := WriteSparse(root, destination, testSpec(root), 0o600, owner)
	if err != nil {
		t.Fatal(err)
	}
	if metadata.SHA256 != second.SHA256 {
		t.Fatal("idempotent write changed identity")
	}
	info, err := os.Stat(destination)
	if err != nil {
		t.Fatal(err)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		t.Fatal("missing Linux stat")
	}
	if int64(stat.Blocks)*512 >= info.Size() {
		t.Fatalf("overlay is not sparse: blocks=%d size=%d", stat.Blocks, info.Size())
	}
	conflict := testSpec(root)
	conflict.VirtualSize += 512
	if _, err := WriteSparse(root, destination, conflict, 0o600, owner); err == nil {
		t.Fatal("conflicting overlay rewrite accepted")
	}
}

func TestWriteSparseRejectsSymlinkParent(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	if err := os.Symlink(outside, filepath.Join(root, "machines")); err != nil {
		t.Fatal(err)
	}
	_, err := WriteSparse(root, filepath.Join(root, "machines", "root.qcow2"), testSpec(root), 0o600, atomicfile.Owner{UID: os.Getuid(), GID: os.Getgid()})
	if err == nil {
		t.Fatal("symlink parent accepted")
	}
}

func TestWriteSparseRejectsUnsafeModeAndWrongExistingOwner(t *testing.T) {
	root := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, "machines"), 0o700); err != nil {
		t.Fatal(err)
	}
	destination := filepath.Join(root, "machines", "root.qcow2")
	owner := atomicfile.Owner{UID: os.Getuid(), GID: os.Getgid()}
	if _, err := WriteSparse(root, destination, testSpec(root), 0o622, owner); err == nil {
		t.Fatal("group/world-writable overlay mode accepted")
	}
	if os.Geteuid() != 0 {
		t.Skip("wrong-owner test requires root")
	}
	image, _, err := Build(testSpec(root))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(destination, image, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(destination, 65534, 65534); err != nil {
		t.Fatal(err)
	}
	if _, err := WriteSparse(root, destination, testSpec(root), 0o600, owner); err == nil {
		t.Fatal("existing overlay with wrong owner accepted")
	}
}
