package guestagent

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/StealthEyeLLC/ehjint/internal/contracts"
	"github.com/StealthEyeLLC/ehjint/internal/guestbuild"
	"github.com/StealthEyeLLC/ehjint/internal/guestproto"
	"github.com/StealthEyeLLC/ehjint/internal/pki"
)

type configFixture struct {
	path     string
	document guestbuild.GuestConfig
}

func createConfigFixture(t *testing.T) configFixture {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("strict root ownership test requires UID 0")
	}
	identifier, err := contracts.NewIdentifierFrom(contracts.MachineIDKind, bytes.NewReader(make([]byte, 16)))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Add(-time.Minute)
	authority, err := pki.GenerateAuthority(now, 365*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	bundle, err := authority.IssueMachine(identifier.String(), now, 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	publicAuthority, err := pki.ParseAuthorityCertificate(authority.CertPEM)
	if err != nil {
		t.Fatal(err)
	}
	guest, err := pki.ParseCredentials(bundle.Guest.CertPEM, bundle.Guest.KeyPEM, pki.RoleGuest, identifier.String(), publicAuthority, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	pkiDir := filepath.Join(root, "pki")
	if err := os.Mkdir(pkiDir, 0o700); err != nil {
		t.Fatal(err)
	}
	paths := map[string]struct {
		data []byte
		mode os.FileMode
	}{
		filepath.Join(pkiDir, "ca.crt"):    {authority.CertPEM, 0o644},
		filepath.Join(pkiDir, "guest.crt"): {bundle.Guest.CertPEM, 0o644},
		filepath.Join(pkiDir, "guest.key"): {bundle.Guest.KeyPEM, 0o600},
	}
	for path, file := range paths {
		if err := os.WriteFile(path, file.data, file.mode); err != nil {
			t.Fatal(err)
		}
		if err := os.Chown(path, 0, 0); err != nil {
			t.Fatal(err)
		}
	}
	document := guestbuild.GuestConfig{
		SchemaVersion: 1, MachineID: identifier.String(), ManifestDigest: strings.Repeat("a", 64),
		AgentVersion: "0.0.0-dev", ProtocolVersion: guestproto.Version, VsockPort: 19000,
		CACertificatePath: filepath.Join(pkiDir, "ca.crt"), CertificatePath: filepath.Join(pkiDir, "guest.crt"), PrivateKeyPath: filepath.Join(pkiDir, "guest.key"),
		GuestCertificateSHA256: testDigest(guest.Certificate.Raw), CACertificateSHA256: testDigest(publicAuthority.Certificate.Raw),
	}
	encoded, err := json.MarshalIndent(document, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	encoded = append(encoded, '\n')
	path := filepath.Join(root, "guest-agent.json")
	if err := os.WriteFile(path, encoded, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(path, 0, 0); err != nil {
		t.Fatal(err)
	}
	return configFixture{path: path, document: document}
}

func TestLoadConfigValidatesPublicTrustAndMachineIdentity(t *testing.T) {
	fixture := createConfigFixture(t)
	loaded, err := LoadConfig(fixture.path, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Document != fixture.document || loaded.Authority.Certificate == nil || len(loaded.Authority.KeyPEM) != 0 || loaded.Credentials.Certificate == nil {
		t.Fatalf("unexpected loaded config: %+v", loaded.Document)
	}
}

func TestLoadConfigRejectsFingerprintModeAndSymlinkFailures(t *testing.T) {
	t.Run("fingerprint", func(t *testing.T) {
		fixture := createConfigFixture(t)
		document := fixture.document
		document.GuestCertificateSHA256 = strings.Repeat("b", 64)
		encoded, err := json.MarshalIndent(document, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(fixture.path, append(encoded, '\n'), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := LoadConfig(fixture.path, time.Now()); err == nil || !strings.Contains(err.Error(), "fingerprint mismatch") {
			t.Fatalf("fingerprint mismatch result: %v", err)
		}
	})
	t.Run("mode", func(t *testing.T) {
		fixture := createConfigFixture(t)
		if err := os.Chmod(fixture.document.PrivateKeyPath, 0o644); err != nil {
			t.Fatal(err)
		}
		if _, err := LoadConfig(fixture.path, time.Now()); err == nil || !strings.Contains(err.Error(), "mode") {
			t.Fatalf("unsafe key mode result: %v", err)
		}
	})
	t.Run("symlink", func(t *testing.T) {
		fixture := createConfigFixture(t)
		realPath := fixture.path + ".real"
		if err := os.Rename(fixture.path, realPath); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(realPath, fixture.path); err != nil {
			t.Fatal(err)
		}
		if _, err := LoadConfig(fixture.path, time.Now()); err == nil || !strings.Contains(err.Error(), "non-symlink") {
			t.Fatalf("symlink config result: %v", err)
		}
	})
}

func TestNewServerRejectsMalformedBootID(t *testing.T) {
	fixture := createConfigFixture(t)
	loaded, err := LoadConfig(fixture.path, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewServer(loaded, "NOT-A-BOOT-ID"); err == nil {
		t.Fatal("malformed boot ID accepted")
	}
}

func testDigest(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}
