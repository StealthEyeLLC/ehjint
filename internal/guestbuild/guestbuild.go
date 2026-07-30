// Package guestbuild deterministically constructs the immutable per-machine
// bootstrap inputs used to turn a verified Ubuntu cloud image into an EHJINT
// guest. Construction does not boot a VM and does not activate later runtime.
package guestbuild

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/StealthEyeLLC/ehjint/internal/cidata"
	"github.com/StealthEyeLLC/ehjint/internal/contracts"
	"github.com/StealthEyeLLC/ehjint/internal/guestproto"
	"github.com/StealthEyeLLC/ehjint/internal/pki"
	"github.com/StealthEyeLLC/ehjint/internal/qcow2"
)

const (
	guestConfigPath = "/etc/ehjint/guest-agent.json"
	guestCAPath     = "/etc/ehjint/pki/ca.crt"
	guestCertPath   = "/etc/ehjint/pki/guest.crt"
	guestKeyPath    = "/etc/ehjint/pki/guest.key"
	guestBinaryPath = "/usr/local/bin/ehjint"
	guestUnitPath   = "/etc/systemd/system/ehjint-guest-agent.service"
	maxBinarySize   = 32 * 1024 * 1024
)

var (
	digestPattern   = regexp.MustCompile(`^[a-f0-9]{64}$`)
	hostnamePattern = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)
)

// Spec binds guest construction to one exact machine and manifest.
type Spec struct {
	MachineID       string
	Hostname        string
	ManifestDigest  string
	AgentVersion    string
	AgentPort       uint32
	Binary          []byte
	Authority       pki.Authority
	Credentials     pki.MachineBundle
	Now             time.Time
	BaseImagePath   string
	BaseImageFormat string
	RootDiskBytes   uint64
}

// GuestConfig is the strict file consumed by internal guest-agent mode.
type GuestConfig struct {
	SchemaVersion          int    `json:"schema_version"`
	MachineID              string `json:"machine_id"`
	ManifestDigest         string `json:"manifest_digest"`
	AgentVersion           string `json:"agent_version"`
	ProtocolVersion        int    `json:"protocol_version"`
	VsockPort              uint32 `json:"vsock_port"`
	CACertificatePath      string `json:"ca_certificate_path"`
	CertificatePath        string `json:"certificate_path"`
	PrivateKeyPath         string `json:"private_key_path"`
	GuestCertificateSHA256 string `json:"guest_certificate_sha256"`
	CACertificateSHA256    string `json:"ca_certificate_sha256"`
}

// Artifacts are exact deterministic bytes ready for durable installation.
type Artifacts struct {
	Overlay         []byte
	OverlayMetadata qcow2.Metadata
	Seed            []byte
	SeedMetadata    cidata.Metadata
	MetaData        []byte
	UserData        []byte
	Config          GuestConfig
	ConfigJSON      []byte
	SystemdUnit     []byte
	BinarySHA256    string
	UserDataSHA256  string
}

// Build validates every binding and creates a QCOW2 overlay plus FAT16 CIDATA
// seed. The same inputs always produce byte-identical outputs.
func Build(spec Spec) (Artifacts, error) {
	if _, err := contracts.ParseIdentifier(contracts.MachineIDKind, spec.MachineID); err != nil {
		return Artifacts{}, fmt.Errorf("invalid guest machine ID: %w", err)
	}
	if !hostnamePattern.MatchString(spec.Hostname) || len(spec.Hostname) > 63 {
		return Artifacts{}, fmt.Errorf("invalid guest hostname")
	}
	if !digestPattern.MatchString(spec.ManifestDigest) {
		return Artifacts{}, fmt.Errorf("manifest digest must be canonical lowercase SHA-256")
	}
	if spec.AgentVersion == "" || len(spec.AgentVersion) > 128 || strings.ContainsRune(spec.AgentVersion, '\x00') {
		return Artifacts{}, fmt.Errorf("invalid guest-agent version")
	}
	if spec.AgentPort == 0 {
		return Artifacts{}, fmt.Errorf("guest-agent vsock port must be nonzero")
	}
	if len(spec.Binary) < 4 || len(spec.Binary) > maxBinarySize || !bytes.Equal(spec.Binary[:4], []byte{0x7f, 'E', 'L', 'F'}) {
		return Artifacts{}, fmt.Errorf("guest agent must be one bounded ELF EHJINT binary")
	}
	if spec.Now.IsZero() {
		return Artifacts{}, fmt.Errorf("explicit construction time is required for credential validation")
	}
	authority, err := pki.ParseAuthority(spec.Authority.CertPEM, spec.Authority.KeyPEM)
	if err != nil {
		return Artifacts{}, fmt.Errorf("validate machine CA: %w", err)
	}
	controller, err := pki.ParseCredentials(spec.Credentials.Controller.CertPEM, spec.Credentials.Controller.KeyPEM, pki.RoleController, spec.MachineID, authority, spec.Now)
	if err != nil {
		return Artifacts{}, fmt.Errorf("validate controller credentials: %w", err)
	}
	guest, err := pki.ParseCredentials(spec.Credentials.Guest.CertPEM, spec.Credentials.Guest.KeyPEM, pki.RoleGuest, spec.MachineID, authority, spec.Now)
	if err != nil {
		return Artifacts{}, fmt.Errorf("validate guest credentials: %w", err)
	}
	_ = controller // validated specifically to ensure a complete paired trust set

	config := GuestConfig{
		SchemaVersion: 1, MachineID: spec.MachineID, ManifestDigest: spec.ManifestDigest,
		AgentVersion: spec.AgentVersion, ProtocolVersion: guestproto.Version, VsockPort: spec.AgentPort,
		CACertificatePath: guestCAPath, CertificatePath: guestCertPath, PrivateKeyPath: guestKeyPath,
		GuestCertificateSHA256: digest(guest.Certificate.Raw), CACertificateSHA256: digest(authority.Certificate.Raw),
	}
	configJSON, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return Artifacts{}, fmt.Errorf("marshal guest config: %w", err)
	}
	configJSON = append(configJSON, '\n')
	unit := []byte(`[Unit]
Description=EHJINT unrestricted root guest agent
After=cloud-final.service
Wants=cloud-final.service
ConditionPathExists=/etc/ehjint/guest-agent.json

[Service]
Type=simple
User=root
Group=root
ExecStart=/usr/local/bin/ehjint internal guest-agent --config /etc/ehjint/guest-agent.json
Restart=on-failure
RestartSec=1s
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
`)
	userData, err := buildUserData(spec.Binary, configJSON, authority.CertPEM, guest.CertPEM, guest.KeyPEM, unit)
	if err != nil {
		return Artifacts{}, err
	}
	for label, secret := range map[string][]byte{"CA private key": authority.KeyPEM, "controller private key": controller.KeyPEM, "controller certificate": controller.CertPEM} {
		encoded := base64.StdEncoding.EncodeToString(secret)
		if bytes.Contains(userData, secret) || bytes.Contains(userData, []byte(encoded)) {
			return Artifacts{}, fmt.Errorf("NoCloud seed leaked %s", label)
		}
	}
	metaData := []byte(fmt.Sprintf("instance-id: %s\nlocal-hostname: %s\n", spec.MachineID, spec.Hostname))
	seed, seedMetadata, err := cidata.BuildNoCloud(metaData, userData)
	if err != nil {
		return Artifacts{}, fmt.Errorf("build NoCloud seed: %w", err)
	}
	overlay, overlayMetadata, err := qcow2.Build(qcow2.Spec{VirtualSize: spec.RootDiskBytes, BackingFile: spec.BaseImagePath, BackingFormat: spec.BaseImageFormat})
	if err != nil {
		return Artifacts{}, fmt.Errorf("build root overlay: %w", err)
	}
	binaryDigest := sha256.Sum256(spec.Binary)
	userDigest := sha256.Sum256(userData)
	return Artifacts{
		Overlay: overlay, OverlayMetadata: overlayMetadata, Seed: seed, SeedMetadata: seedMetadata,
		MetaData: metaData, UserData: userData, Config: config, ConfigJSON: configJSON, SystemdUnit: unit,
		BinarySHA256: hex.EncodeToString(binaryDigest[:]), UserDataSHA256: hex.EncodeToString(userDigest[:]),
	}, nil
}

type cloudFile struct {
	path        string
	permissions string
	encoding    string
	content     []byte
}

func buildUserData(binary, config, caCert, guestCert, guestKey, unit []byte) ([]byte, error) {
	compressed, err := gzipDeterministic(binary)
	if err != nil {
		return nil, err
	}
	files := []cloudFile{
		{guestBinaryPath, "0755", "gzip+base64", compressed},
		{guestConfigPath, "0600", "base64", config},
		{guestCAPath, "0644", "base64", caCert},
		{guestCertPath, "0644", "base64", guestCert},
		{guestKeyPath, "0600", "base64", guestKey},
		{guestUnitPath, "0644", "base64", unit},
	}
	var output strings.Builder
	output.WriteString("#cloud-config\n")
	output.WriteString("ssh_pwauth: false\n")
	output.WriteString("ssh_deletekeys: true\n")
	output.WriteString("disable_root: true\n")
	output.WriteString("write_files:\n")
	for _, file := range files {
		output.WriteString("  - path: ")
		output.WriteString(file.path)
		output.WriteString("\n    owner: root:root\n    permissions: '")
		output.WriteString(file.permissions)
		output.WriteString("'\n    encoding: ")
		output.WriteString(file.encoding)
		output.WriteString("\n    content: |\n")
		writeWrappedBase64(&output, file.content)
	}
	output.WriteString("runcmd:\n")
	output.WriteString("  - [ systemctl, mask, ssh.service, ssh.socket ]\n")
	output.WriteString("  - [ systemctl, daemon-reload ]\n")
	output.WriteString("  - [ systemctl, enable, --now, ehjint-guest-agent.service ]\n")
	output.WriteString("final_message: 'EHJINT guest bootstrap complete'\n")
	return []byte(output.String()), nil
}

func gzipDeterministic(data []byte) ([]byte, error) {
	var output bytes.Buffer
	writer, err := gzip.NewWriterLevel(&output, gzip.BestCompression)
	if err != nil {
		return nil, fmt.Errorf("create deterministic guest binary compressor: %w", err)
	}
	writer.Header.ModTime = time.Unix(0, 0).UTC()
	writer.Header.Name = ""
	writer.Header.Comment = ""
	writer.Header.OS = 255
	if _, err := writer.Write(data); err != nil {
		_ = writer.Close()
		return nil, fmt.Errorf("compress guest binary: %w", err)
	}
	if err := writer.Close(); err != nil {
		return nil, fmt.Errorf("finish guest binary compression: %w", err)
	}
	return output.Bytes(), nil
}

func writeWrappedBase64(output *strings.Builder, data []byte) {
	encoded := base64.StdEncoding.EncodeToString(data)
	for len(encoded) > 0 {
		count := 76
		if len(encoded) < count {
			count = len(encoded)
		}
		output.WriteString("      ")
		output.WriteString(encoded[:count])
		output.WriteByte('\n')
		encoded = encoded[count:]
	}
}

func digest(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}
