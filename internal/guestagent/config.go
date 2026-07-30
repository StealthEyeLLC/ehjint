// Package guestagent implements EHJINT's machine-bound unrestricted-root guest
// execution authority. It is reachable only through authenticated guest
// transport and executes no host-side commands.
package guestagent

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"syscall"
	"time"

	"github.com/StealthEyeLLC/ehjint/internal/contracts"
	"github.com/StealthEyeLLC/ehjint/internal/guestbuild"
	"github.com/StealthEyeLLC/ehjint/internal/guestproto"
	"github.com/StealthEyeLLC/ehjint/internal/pki"
)

var sha256Pattern = regexp.MustCompile(`^[a-f0-9]{64}$`)

// RuntimeConfig is a fully parsed guest identity ready to serve.
type RuntimeConfig struct {
	Document    guestbuild.GuestConfig
	Authority   pki.Authority
	Credentials pki.Credentials
}

// LoadConfig strictly loads root-owned, non-symlinked guest configuration and
// machine credentials. The guest receives only the public CA certificate.
func LoadConfig(path string, now time.Time) (RuntimeConfig, error) {
	if os.Geteuid() != 0 {
		return RuntimeConfig{}, fmt.Errorf("guest-agent mode requires UID 0")
	}
	if err := requireRootFile(path, 0o600); err != nil {
		return RuntimeConfig{}, fmt.Errorf("guest config: %w", err)
	}
	encoded, err := os.ReadFile(path)
	if err != nil {
		return RuntimeConfig{}, fmt.Errorf("read guest config: %w", err)
	}
	var document guestbuild.GuestConfig
	if err := contracts.DecodeStrict(encoded, &document); err != nil {
		return RuntimeConfig{}, fmt.Errorf("decode guest config: %w", err)
	}
	if err := validateDocument(document); err != nil {
		return RuntimeConfig{}, err
	}
	if err := requireRootFile(document.CACertificatePath, 0o644); err != nil {
		return RuntimeConfig{}, fmt.Errorf("guest CA certificate: %w", err)
	}
	if err := requireRootFile(document.CertificatePath, 0o644); err != nil {
		return RuntimeConfig{}, fmt.Errorf("guest certificate: %w", err)
	}
	if err := requireRootFile(document.PrivateKeyPath, 0o600); err != nil {
		return RuntimeConfig{}, fmt.Errorf("guest private key: %w", err)
	}
	caPEM, err := os.ReadFile(document.CACertificatePath)
	if err != nil {
		return RuntimeConfig{}, fmt.Errorf("read guest CA certificate: %w", err)
	}
	certPEM, err := os.ReadFile(document.CertificatePath)
	if err != nil {
		return RuntimeConfig{}, fmt.Errorf("read guest certificate: %w", err)
	}
	keyPEM, err := os.ReadFile(document.PrivateKeyPath)
	if err != nil {
		return RuntimeConfig{}, fmt.Errorf("read guest private key: %w", err)
	}
	authority, err := pki.ParseAuthorityCertificate(caPEM)
	if err != nil {
		return RuntimeConfig{}, fmt.Errorf("parse guest public CA: %w", err)
	}
	credentials, err := pki.ParseCredentials(certPEM, keyPEM, pki.RoleGuest, document.MachineID, authority, now)
	if err != nil {
		return RuntimeConfig{}, fmt.Errorf("parse guest identity: %w", err)
	}
	if digest(authority.Certificate.Raw) != document.CACertificateSHA256 {
		return RuntimeConfig{}, fmt.Errorf("guest CA certificate fingerprint mismatch")
	}
	if digest(credentials.Certificate.Raw) != document.GuestCertificateSHA256 {
		return RuntimeConfig{}, fmt.Errorf("guest certificate fingerprint mismatch")
	}
	return RuntimeConfig{Document: document, Authority: authority, Credentials: credentials}, nil
}

func validateDocument(document guestbuild.GuestConfig) error {
	if document.SchemaVersion != 1 {
		return fmt.Errorf("unsupported guest config schema version %d", document.SchemaVersion)
	}
	if _, err := contracts.ParseIdentifier(contracts.MachineIDKind, document.MachineID); err != nil {
		return fmt.Errorf("invalid guest config machine ID: %w", err)
	}
	if !sha256Pattern.MatchString(document.ManifestDigest) || !sha256Pattern.MatchString(document.GuestCertificateSHA256) || !sha256Pattern.MatchString(document.CACertificateSHA256) {
		return fmt.Errorf("guest config contains an invalid SHA-256 identity")
	}
	if document.AgentVersion == "" || len(document.AgentVersion) > 128 {
		return fmt.Errorf("invalid guest-agent version")
	}
	if document.ProtocolVersion != guestproto.Version || document.VsockPort == 0 {
		return fmt.Errorf("unsupported guest protocol or vsock port")
	}
	for label, path := range map[string]string{
		"CA certificate": document.CACertificatePath,
		"certificate":    document.CertificatePath,
		"private key":    document.PrivateKeyPath,
	} {
		if !filepath.IsAbs(path) || filepath.Clean(path) != path {
			return fmt.Errorf("guest %s path must be canonical absolute path", label)
		}
	}
	return nil
}

func requireRootFile(path string, mode os.FileMode) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return fmt.Errorf("path must be canonical absolute path")
	}
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("path is not a regular non-symlink file")
	}
	if info.Mode().Perm() != mode.Perm() {
		return fmt.Errorf("mode is %04o, expected %04o", info.Mode().Perm(), mode.Perm())
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != 0 || stat.Gid != 0 {
		return fmt.Errorf("file must be owned by root:root")
	}
	return nil
}

func digest(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}
