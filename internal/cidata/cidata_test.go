package cidata

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestBuildNoCloudIsDeterministicAndExtractable(t *testing.T) {
	meta := []byte("instance-id: mach_test\nlocal-hostname: ehjint-test\n")
	user := []byte("#cloud-config\nwrite_files: []\n")
	first, metadata, err := BuildNoCloud(meta, user)
	if err != nil {
		t.Fatal(err)
	}
	second, secondMetadata, err := BuildNoCloud(meta, user)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first, second) || metadata.SHA256 != secondMetadata.SHA256 || metadata.VolumeID != secondMetadata.VolumeID {
		t.Fatal("CIDATA construction is not deterministic")
	}
	if !bytes.Equal(metadata.Files["meta-data"], meta) || !bytes.Equal(metadata.Files["user-data"], user) {
		t.Fatal("CIDATA files did not round-trip")
	}
	if metadata.DataClusters < minimumClusters {
		t.Fatal("image is not FAT16")
	}
}

func TestBuildNoCloudPassesFSCK(t *testing.T) {
	tool, err := exec.LookPath("fsck.fat")
	if err != nil {
		t.Skip("fsck.fat is not installed")
	}
	image, _, err := BuildNoCloud([]byte("instance-id: test\n"), []byte("#cloud-config\n{}\n"))
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "seed.img")
	if err := os.WriteFile(path, image, 0o600); err != nil {
		t.Fatal(err)
	}
	command := exec.Command(tool, "-n", path)
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("fsck.fat failed: %v\n%s", err, output)
	}
}

func TestInspectRejectsCorruption(t *testing.T) {
	image, _, err := BuildNoCloud([]byte("instance-id: test\n"), []byte("#cloud-config\n{}\n"))
	if err != nil {
		t.Fatal(err)
	}
	cases := map[string]func([]byte){
		"signature": func(data []byte) { data[510] = 0 },
		"label":     func(data []byte) { data[43] = 'X' },
		"second FAT": func(data []byte) {
			fatSectors := int(data[22]) | int(data[23])<<8
			data[(reservedSectors+fatSectors)*sectorSize+4] ^= 1
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			candidate := append([]byte(nil), image...)
			mutate(candidate)
			if _, err := Inspect(candidate); err == nil {
				t.Fatal("corrupt CIDATA accepted")
			}
		})
	}
}

func TestBuildNoCloudRejectsMissingAndOversizedContent(t *testing.T) {
	if _, _, err := BuildNoCloud(nil, []byte("x")); err == nil {
		t.Fatal("missing metadata accepted")
	}
	tooLarge := make([]byte, maximumClusters*sectorSize)
	if _, _, err := BuildNoCloud([]byte("x"), tooLarge); err == nil {
		t.Fatal("oversized seed accepted")
	}
}
