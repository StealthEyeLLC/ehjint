package guestbuild

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/StealthEyeLLC/ehjint/internal/cidata"
	"github.com/StealthEyeLLC/ehjint/internal/contracts"
	"github.com/StealthEyeLLC/ehjint/internal/pki"
	"github.com/StealthEyeLLC/ehjint/internal/qcow2"
)

func fixture(t *testing.T) Spec {
	t.Helper()
	machine, err := contracts.NewIdentifierFrom(contracts.MachineIDKind, bytes.NewReader(make([]byte, 16)))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 7, 30, 12, 0, 0, 0, time.UTC)
	authority, err := pki.GenerateAuthority(now, 365*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	bundle, err := authority.IssueMachine(machine.String(), now, 90*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	binary := append([]byte{0x7f, 'E', 'L', 'F'}, bytes.Repeat([]byte("ehjint"), 1024)...)
	return Spec{
		MachineID: machine.String(), Hostname: "ehjint-default",
		ManifestDigest: strings.Repeat("a", 64), AgentVersion: "0.0.0-dev", AgentPort: 19000,
		Binary: binary, Authority: authority, Credentials: bundle, Now: now,
		BaseImagePath: "/var/lib/ehjint/images/sha256/aaaaaaaa/root.img", BaseImageFormat: "qcow2",
		RootDiskBytes: 32 * 1024 * 1024 * 1024,
	}
}

func TestBuildIsDeterministicAndBound(t *testing.T) {
	spec := fixture(t)
	first, err := Build(spec)
	if err != nil {
		t.Fatal(err)
	}
	second, err := Build(spec)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first.Overlay, second.Overlay) || !bytes.Equal(first.Seed, second.Seed) || first.SeedMetadata.SHA256 != second.SeedMetadata.SHA256 {
		t.Fatal("guest construction is not deterministic for identical bound inputs")
	}
	if _, err := qcow2.Inspect(first.Overlay); err != nil {
		t.Fatal(err)
	}
	seed, err := cidata.Inspect(first.Seed)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(seed.Files["meta-data"], first.MetaData) || !bytes.Equal(seed.Files["user-data"], first.UserData) {
		t.Fatal("seed payload differs from construction artifacts")
	}
	if first.Config.MachineID != spec.MachineID || first.Config.ManifestDigest != spec.ManifestDigest || first.Config.VsockPort != spec.AgentPort {
		t.Fatalf("guest config lost binding: %+v", first.Config)
	}
	var decoded GuestConfig
	if err := json.Unmarshal(first.ConfigJSON, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded != first.Config {
		t.Fatal("serialized guest config differs")
	}
	for _, required := range []string{guestBinaryPath, guestConfigPath, guestCAPath, guestCertPath, guestKeyPath, guestUnitPath, "ssh_deletekeys: true"} {
		if !bytes.Contains(first.UserData, []byte(required)) {
			t.Fatalf("user-data lacks %q", required)
		}
	}
	if !containsWrappedBase64(first.UserData, first.SystemdUnit) {
		t.Fatal("user-data lacks encoded guest-agent systemd unit")
	}
}

func TestSeedContainsGuestTrustButNoHostSecrets(t *testing.T) {
	spec := fixture(t)
	artifacts, err := Build(spec)
	if err != nil {
		t.Fatal(err)
	}
	for label, secret := range map[string][]byte{
		"CA private key":         spec.Authority.KeyPEM,
		"controller key":         spec.Credentials.Controller.KeyPEM,
		"controller certificate": spec.Credentials.Controller.CertPEM,
	} {
		if bytes.Contains(artifacts.UserData, secret) || bytes.Contains(artifacts.UserData, []byte(base64.StdEncoding.EncodeToString(secret))) {
			t.Fatalf("seed contains %s", label)
		}
	}
	for label, material := range map[string][]byte{"CA certificate": spec.Authority.CertPEM, "guest certificate": spec.Credentials.Guest.CertPEM, "guest key": spec.Credentials.Guest.KeyPEM} {
		if !containsWrappedBase64(artifacts.UserData, material) {
			t.Fatalf("seed lacks encoded %s", label)
		}
	}
}

func TestBuildRejectsCrossMachineAndMalformedInputs(t *testing.T) {
	original := fixture(t)
	other, err := contracts.NewIdentifierFrom(contracts.MachineIDKind, bytes.NewReader(bytes.Repeat([]byte{1}, 16)))
	if err != nil {
		t.Fatal(err)
	}
	cases := map[string]func(*Spec){
		"cross-machine credentials": func(spec *Spec) { spec.MachineID = other.String() },
		"manifest digest":           func(spec *Spec) { spec.ManifestDigest = "ABC" },
		"hostname":                  func(spec *Spec) { spec.Hostname = "bad_name" },
		"agent port":                func(spec *Spec) { spec.AgentPort = 0 },
		"not ELF":                   func(spec *Spec) { spec.Binary = []byte("script") },
		"implicit format":           func(spec *Spec) { spec.BaseImageFormat = "" },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			spec := original
			mutate(&spec)
			if _, err := Build(spec); err == nil {
				t.Fatal("invalid guest construction accepted")
			}
		})
	}
}

func TestDeterministicCompression(t *testing.T) {
	data := bytes.Repeat([]byte("binary"), 4096)
	first, err := gzipDeterministic(data)
	if err != nil {
		t.Fatal(err)
	}
	second, err := gzipDeterministic(data)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first, second) {
		t.Fatal("gzip output is not deterministic")
	}
}

func containsWrappedBase64(document, material []byte) bool {
	var wrapped strings.Builder
	writeWrappedBase64(&wrapped, material)
	return bytes.Contains(document, []byte(wrapped.String()))
}
