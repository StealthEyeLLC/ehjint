// Package qcow2 creates and validates the narrow QCOW2 v3 overlay shape used
// by EHJINT. It never guesses a disk format and never invokes qemu-img.
package qcow2

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"syscall"

	"github.com/StealthEyeLLC/ehjint/internal/atomicfile"
	"github.com/StealthEyeLLC/ehjint/internal/layout"
)

const (
	magic                         = 0x514649fb
	version                       = 3
	clusterBits                   = 16
	clusterSize                   = 1 << clusterBits
	headerLength                  = 104
	backingFormatExtension        = 0xe2792aca
	backingFileOffset             = 128
	l1TableOffset                 = clusterSize
	refcountTableOffset           = 2 * clusterSize
	refcountBlockOffset           = 3 * clusterSize
	physicalImageSize             = 4 * clusterSize
	refcountOrder                 = 4
	minimumVirtualSize     uint64 = 1024 * 1024
)

// Spec is the complete immutable empty-overlay contract.
type Spec struct {
	VirtualSize   uint64
	BackingFile   string
	BackingFormat string
}

// Metadata is the strictly inspected canonical overlay identity.
type Metadata struct {
	Version             uint32
	ClusterBits         uint32
	VirtualSize         uint64
	BackingFile         string
	BackingFormat       string
	L1Size              uint32
	L1TableOffset       uint64
	RefcountTableOffset uint64
	RefcountBlockOffset uint64
	PhysicalSize        int64
	SHA256              string
}

// Build returns the deterministic logical bytes of an empty QCOW2 v3 overlay.
func Build(spec Spec) ([]byte, Metadata, error) {
	l1Size, err := validateSpec(spec)
	if err != nil {
		return nil, Metadata{}, err
	}
	image := make([]byte, physicalImageSize)
	binary.BigEndian.PutUint32(image[0:4], magic)
	binary.BigEndian.PutUint32(image[4:8], version)
	binary.BigEndian.PutUint64(image[8:16], backingFileOffset)
	binary.BigEndian.PutUint32(image[16:20], uint32(len(spec.BackingFile)))
	binary.BigEndian.PutUint32(image[20:24], clusterBits)
	binary.BigEndian.PutUint64(image[24:32], spec.VirtualSize)
	binary.BigEndian.PutUint32(image[32:36], 0) // no encryption
	binary.BigEndian.PutUint32(image[36:40], l1Size)
	binary.BigEndian.PutUint64(image[40:48], l1TableOffset)
	binary.BigEndian.PutUint64(image[48:56], refcountTableOffset)
	binary.BigEndian.PutUint32(image[56:60], 1)
	binary.BigEndian.PutUint32(image[60:64], 0)
	binary.BigEndian.PutUint64(image[64:72], 0)
	binary.BigEndian.PutUint64(image[72:80], 0)
	binary.BigEndian.PutUint64(image[80:88], 0)
	binary.BigEndian.PutUint64(image[88:96], 0)
	binary.BigEndian.PutUint32(image[96:100], refcountOrder)
	binary.BigEndian.PutUint32(image[100:104], headerLength)

	binary.BigEndian.PutUint32(image[104:108], backingFormatExtension)
	binary.BigEndian.PutUint32(image[108:112], uint32(len(spec.BackingFormat)))
	copy(image[112:120], spec.BackingFormat)
	// The extension payload is padded to 8 bytes. The zero extension at 120
	// terminates the list before the backing filename begins at 128.
	copy(image[backingFileOffset:], spec.BackingFile)

	binary.BigEndian.PutUint64(image[refcountTableOffset:refcountTableOffset+8], refcountBlockOffset)
	for index := 0; index < 4; index++ {
		binary.BigEndian.PutUint16(image[refcountBlockOffset+index*2:], 1)
	}
	metadata, err := Inspect(image)
	if err != nil {
		return nil, Metadata{}, fmt.Errorf("inspect constructed QCOW2 overlay: %w", err)
	}
	return image, metadata, nil
}

// Inspect accepts only EHJINT's canonical empty-overlay shape.
func Inspect(image []byte) (Metadata, error) {
	if len(image) != physicalImageSize {
		return Metadata{}, fmt.Errorf("QCOW2 physical size must be %d bytes", physicalImageSize)
	}
	if binary.BigEndian.Uint32(image[0:4]) != magic {
		return Metadata{}, fmt.Errorf("invalid QCOW2 magic")
	}
	if binary.BigEndian.Uint32(image[4:8]) != version {
		return Metadata{}, fmt.Errorf("unsupported QCOW2 version")
	}
	backingOffset := binary.BigEndian.Uint64(image[8:16])
	backingSize := binary.BigEndian.Uint32(image[16:20])
	bits := binary.BigEndian.Uint32(image[20:24])
	virtualSize := binary.BigEndian.Uint64(image[24:32])
	l1Size := binary.BigEndian.Uint32(image[36:40])
	l1Offset := binary.BigEndian.Uint64(image[40:48])
	refTableOffset := binary.BigEndian.Uint64(image[48:56])
	if backingOffset != backingFileOffset || bits != clusterBits || l1Offset != l1TableOffset || refTableOffset != refcountTableOffset {
		return Metadata{}, fmt.Errorf("non-canonical QCOW2 layout")
	}
	if binary.BigEndian.Uint32(image[32:36]) != 0 || binary.BigEndian.Uint32(image[56:60]) != 1 ||
		binary.BigEndian.Uint32(image[60:64]) != 0 || binary.BigEndian.Uint64(image[64:72]) != 0 ||
		binary.BigEndian.Uint64(image[72:80]) != 0 || binary.BigEndian.Uint64(image[80:88]) != 0 ||
		binary.BigEndian.Uint64(image[88:96]) != 0 || binary.BigEndian.Uint32(image[96:100]) != refcountOrder ||
		binary.BigEndian.Uint32(image[100:104]) != headerLength {
		return Metadata{}, fmt.Errorf("unsupported QCOW2 feature or header field")
	}
	if backingSize == 0 || int(backingOffset)+int(backingSize) > clusterSize {
		return Metadata{}, fmt.Errorf("invalid QCOW2 backing filename bounds")
	}
	if binary.BigEndian.Uint32(image[104:108]) != backingFormatExtension {
		return Metadata{}, fmt.Errorf("explicit QCOW2 backing format extension is missing")
	}
	formatSize := binary.BigEndian.Uint32(image[108:112])
	if formatSize == 0 || formatSize > 8 {
		return Metadata{}, fmt.Errorf("invalid QCOW2 backing format length")
	}
	format := string(image[112 : 112+formatSize])
	if binary.BigEndian.Uint32(image[120:124]) != 0 || binary.BigEndian.Uint32(image[124:128]) != 0 {
		return Metadata{}, fmt.Errorf("QCOW2 extension list is not terminated")
	}
	backing := string(image[backingOffset : backingOffset+uint64(backingSize)])
	spec := Spec{VirtualSize: virtualSize, BackingFile: backing, BackingFormat: format}
	expectedL1, err := validateSpec(spec)
	if err != nil {
		return Metadata{}, err
	}
	if l1Size != expectedL1 {
		return Metadata{}, fmt.Errorf("QCOW2 L1 size mismatch")
	}
	if !allZero(image[l1TableOffset:refcountTableOffset]) {
		return Metadata{}, fmt.Errorf("new QCOW2 overlay has allocated guest clusters")
	}
	if binary.BigEndian.Uint64(image[refcountTableOffset:refcountTableOffset+8]) != refcountBlockOffset ||
		!allZero(image[refcountTableOffset+8:refcountBlockOffset]) {
		return Metadata{}, fmt.Errorf("invalid QCOW2 refcount table")
	}
	for index := 0; index < 4; index++ {
		if binary.BigEndian.Uint16(image[refcountBlockOffset+index*2:]) != 1 {
			return Metadata{}, fmt.Errorf("invalid QCOW2 metadata refcount at cluster %d", index)
		}
	}
	if !allZero(image[refcountBlockOffset+8:]) {
		return Metadata{}, fmt.Errorf("new QCOW2 overlay contains unexpected allocated refcounts")
	}
	digest := sha256.Sum256(image)
	return Metadata{
		Version: version, ClusterBits: bits, VirtualSize: virtualSize,
		BackingFile: backing, BackingFormat: format, L1Size: l1Size,
		L1TableOffset: l1Offset, RefcountTableOffset: refTableOffset,
		RefcountBlockOffset: refcountBlockOffset, PhysicalSize: int64(len(image)),
		SHA256: hex.EncodeToString(digest[:]),
	}, nil
}

// WriteSparse installs the deterministic overlay atomically while retaining
// holes for the all-zero L1 table and unused refcount space.
func WriteSparse(root, destination string, spec Spec, mode fs.FileMode, owner atomicfile.Owner) (Metadata, error) {
	if mode.Perm() == 0 || mode.Perm()&0o022 != 0 || mode&^fs.ModePerm != 0 {
		return Metadata{}, fmt.Errorf("unsafe QCOW2 mode %04o", mode)
	}
	image, metadata, err := Build(spec)
	if err != nil {
		return Metadata{}, err
	}
	cleanRoot, cleanDestination, parent, err := validateDestination(root, destination, owner)
	if err != nil {
		return Metadata{}, err
	}
	if existing, readErr := os.ReadFile(cleanDestination); readErr == nil {
		if err := verifyInstalledFile(cleanDestination, mode, owner); err != nil {
			return Metadata{}, err
		}
		inspected, inspectErr := Inspect(existing)
		if inspectErr == nil && bytes.Equal(existing, image) {
			return inspected, nil
		}
		return Metadata{}, fmt.Errorf("existing QCOW2 overlay differs from requested immutable construction")
	} else if !os.IsNotExist(readErr) {
		return Metadata{}, fmt.Errorf("read existing QCOW2 overlay: %w", readErr)
	}

	temporary, err := os.CreateTemp(parent, ".ehjint-qcow2-")
	if err != nil {
		return Metadata{}, fmt.Errorf("create QCOW2 temporary file: %w", err)
	}
	temporaryName := temporary.Name()
	defer func() { _ = os.Remove(temporaryName) }()
	if err := temporary.Chmod(0o600); err != nil {
		_ = temporary.Close()
		return Metadata{}, fmt.Errorf("restrict QCOW2 temporary file: %w", err)
	}
	if err := temporary.Chown(owner.UID, owner.GID); err != nil {
		_ = temporary.Close()
		return Metadata{}, fmt.Errorf("set QCOW2 owner: %w", err)
	}
	if err := temporary.Truncate(int64(len(image))); err != nil {
		_ = temporary.Close()
		return Metadata{}, fmt.Errorf("size sparse QCOW2 overlay: %w", err)
	}
	segments := []struct {
		offset int64
		data   []byte
	}{
		{0, image[:clusterSize]},
		{refcountTableOffset, image[refcountTableOffset : refcountTableOffset+8]},
		{refcountBlockOffset, image[refcountBlockOffset : refcountBlockOffset+8]},
	}
	for _, segment := range segments {
		if _, err := temporary.WriteAt(segment.data, segment.offset); err != nil {
			_ = temporary.Close()
			return Metadata{}, fmt.Errorf("write sparse QCOW2 segment: %w", err)
		}
	}
	if err := temporary.Chmod(mode.Perm()); err != nil {
		_ = temporary.Close()
		return Metadata{}, fmt.Errorf("set QCOW2 mode: %w", err)
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return Metadata{}, fmt.Errorf("fsync QCOW2 overlay: %w", err)
	}
	if err := temporary.Close(); err != nil {
		return Metadata{}, fmt.Errorf("close QCOW2 overlay: %w", err)
	}
	if err := os.Rename(temporaryName, cleanDestination); err != nil {
		return Metadata{}, fmt.Errorf("install QCOW2 overlay atomically: %w", err)
	}
	directory, err := os.Open(parent)
	if err != nil {
		return Metadata{}, fmt.Errorf("open QCOW2 parent for fsync: %w", err)
	}
	if err := directory.Sync(); err != nil {
		_ = directory.Close()
		return Metadata{}, fmt.Errorf("fsync QCOW2 parent: %w", err)
	}
	if err := directory.Close(); err != nil {
		return Metadata{}, fmt.Errorf("close QCOW2 parent: %w", err)
	}
	installed, err := os.ReadFile(cleanDestination)
	if err != nil {
		return Metadata{}, fmt.Errorf("reopen installed QCOW2 overlay: %w", err)
	}
	if !bytes.Equal(installed, image) {
		return Metadata{}, fmt.Errorf("installed sparse QCOW2 bytes differ from deterministic image")
	}
	if err := verifyInstalledFile(cleanDestination, mode, owner); err != nil {
		return Metadata{}, err
	}
	if !layout.Within(cleanRoot, cleanDestination) {
		return Metadata{}, fmt.Errorf("installed QCOW2 escaped managed root")
	}
	return metadata, nil
}

func validateSpec(spec Spec) (uint32, error) {
	if spec.BackingFormat != "qcow2" && spec.BackingFormat != "raw" {
		return 0, fmt.Errorf("backing format must be explicitly qcow2 or raw")
	}
	if !filepath.IsAbs(spec.BackingFile) || filepath.Clean(spec.BackingFile) != spec.BackingFile ||
		len(spec.BackingFile) == 0 || len(spec.BackingFile) > clusterSize-backingFileOffset || bytes.IndexByte([]byte(spec.BackingFile), 0) >= 0 {
		return 0, fmt.Errorf("backing filename must be a bounded canonical absolute path")
	}
	if spec.VirtualSize < minimumVirtualSize || spec.VirtualSize%512 != 0 {
		return 0, fmt.Errorf("virtual size must be at least 1 MiB and 512-byte aligned")
	}
	entriesPerL2 := uint64(clusterSize / 8)
	coveragePerL1 := uint64(clusterSize) * entriesPerL2
	l1Size := (spec.VirtualSize + coveragePerL1 - 1) / coveragePerL1
	if l1Size == 0 || l1Size > uint64(clusterSize/8) {
		return 0, fmt.Errorf("virtual size exceeds the canonical single-cluster L1 table")
	}
	return uint32(l1Size), nil
}

func validateDestination(root, destination string, owner atomicfile.Owner) (string, string, string, error) {
	if owner.UID < 0 || owner.GID < 0 {
		return "", "", "", fmt.Errorf("QCOW2 owner must be explicit")
	}
	cleanRoot := filepath.Clean(root)
	cleanDestination := filepath.Clean(destination)
	if !filepath.IsAbs(cleanRoot) || !filepath.IsAbs(cleanDestination) || !layout.Within(cleanRoot, cleanDestination) {
		return "", "", "", fmt.Errorf("QCOW2 destination escapes managed root")
	}
	parent := filepath.Dir(cleanDestination)
	current := cleanRoot
	rootInfo, err := os.Lstat(current)
	if err != nil || !rootInfo.IsDir() || rootInfo.Mode()&os.ModeSymlink != 0 || rootInfo.Mode().Perm()&0o002 != 0 {
		return "", "", "", fmt.Errorf("QCOW2 managed root is not a safe real directory")
	}
	relative, err := filepath.Rel(cleanRoot, parent)
	if err != nil || relative == ".." || filepath.IsAbs(relative) {
		return "", "", "", fmt.Errorf("QCOW2 parent escapes managed root")
	}
	if relative != "." {
		for _, component := range split(relative) {
			current = filepath.Join(current, component)
			info, statErr := os.Lstat(current)
			if statErr != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o002 != 0 {
				return "", "", "", fmt.Errorf("QCOW2 parent component is not a safe real directory")
			}
		}
	}
	if info, err := os.Lstat(cleanDestination); err == nil {
		if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
			return "", "", "", fmt.Errorf("existing QCOW2 destination is not a regular file")
		}
	} else if !os.IsNotExist(err) {
		return "", "", "", fmt.Errorf("inspect QCOW2 destination: %w", err)
	}
	return cleanRoot, cleanDestination, parent, nil
}

func verifyInstalledFile(path string, mode fs.FileMode, owner atomicfile.Owner) error {
	info, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("inspect installed QCOW2 overlay: %w", err)
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("installed QCOW2 overlay is not a regular file")
	}
	if info.Mode().Perm() != mode.Perm() {
		return fmt.Errorf("installed QCOW2 mode is %04o, expected %04o", info.Mode().Perm(), mode.Perm())
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("installed QCOW2 ownership is unavailable")
	}
	if int(stat.Uid) != owner.UID || int(stat.Gid) != owner.GID {
		return fmt.Errorf("installed QCOW2 owner is %d:%d, expected %d:%d", stat.Uid, stat.Gid, owner.UID, owner.GID)
	}
	return nil
}

func split(relative string) []string {
	var result []string
	for relative != "." && relative != "" {
		directory, file := filepath.Split(relative)
		if file != "" {
			result = append([]string{file}, result...)
		}
		relative = filepath.Clean(directory)
		if relative == string(filepath.Separator) {
			break
		}
	}
	return result
}

func allZero(data []byte) bool {
	for _, value := range data {
		if value != 0 {
			return false
		}
	}
	return true
}
