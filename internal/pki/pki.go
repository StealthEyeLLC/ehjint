// Package pki owns EHJINT's private controller CA and per-machine mutually
// authenticated TLS identities. AF_VSOCK reachability is transport only; the
// expected role and exact machine ID are authenticated by URI SANs.
package pki

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/StealthEyeLLC/ehjint/internal/atomicfile"
	"github.com/StealthEyeLLC/ehjint/internal/contracts"
)

const (
	RoleController = "controller"
	RoleGuest      = "guest"
	ALPN           = "ehjint-vsock/1"
	identityScheme = "spiffe"
	identityHost   = "ehjint.local"
)

// Authority is the parsed private CA authority.
type Authority struct {
	Certificate *x509.Certificate
	PrivateKey  ed25519.PrivateKey
	CertPEM     []byte
	KeyPEM      []byte
}

// Credentials contains exactly one leaf identity.
type Credentials struct {
	Certificate *x509.Certificate
	TLS         tls.Certificate
	CertPEM     []byte
	KeyPEM      []byte
	Role        string
	MachineID   string
}

// MachineBundle separates host-controller and guest-server private keys.
type MachineBundle struct {
	Controller Credentials
	Guest      Credentials
}

// GenerateAuthority creates a private Ed25519 root CA.
func GenerateAuthority(now time.Time, validity time.Duration) (Authority, error) {
	if validity < 24*time.Hour || validity > 20*365*24*time.Hour {
		return Authority{}, fmt.Errorf("CA validity is outside 1 day..20 years")
	}
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return Authority{}, fmt.Errorf("generate controller CA key: %w", err)
	}
	serial, err := randomSerial(rand.Reader)
	if err != nil {
		return Authority{}, err
	}
	now = now.UTC()
	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "EHJINT Private Controller Root", Organization: []string{"StealthEye LLC"}},
		NotBefore:             now.Add(-5 * time.Minute),
		NotAfter:              now.Add(validity),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0,
		MaxPathLenZero:        true,
		SubjectKeyId:          publicKey,
	}
	certificateDER, err := x509.CreateCertificate(rand.Reader, template, template, publicKey, privateKey)
	if err != nil {
		return Authority{}, fmt.Errorf("create controller CA certificate: %w", err)
	}
	certificate, err := x509.ParseCertificate(certificateDER)
	if err != nil {
		return Authority{}, fmt.Errorf("parse generated controller CA certificate: %w", err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return Authority{}, fmt.Errorf("marshal controller CA key: %w", err)
	}
	return Authority{
		Certificate: certificate,
		PrivateKey:  privateKey,
		CertPEM:     pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificateDER}),
		KeyPEM:      pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}),
	}, nil
}

// ParseAuthorityCertificate parses the public half of one constrained EHJINT
// CA. Guest machines use this form and never receive the CA private key.
func ParseAuthorityCertificate(certPEM []byte) (Authority, error) {
	certificate, err := parseSingleCertificate(certPEM)
	if err != nil {
		return Authority{}, err
	}
	if !certificate.IsCA || !certificate.BasicConstraintsValid || certificate.MaxPathLen != 0 || !certificate.MaxPathLenZero || certificate.KeyUsage&x509.KeyUsageCertSign == 0 {
		return Authority{}, fmt.Errorf("certificate is not the constrained EHJINT CA shape")
	}
	if _, ok := certificate.PublicKey.(ed25519.PublicKey); !ok {
		return Authority{}, fmt.Errorf("EHJINT CA public key is not Ed25519")
	}
	return Authority{Certificate: certificate, CertPEM: append([]byte(nil), certPEM...)}, nil
}

// ParseAuthority parses exactly one CA certificate and Ed25519 private key and
// verifies that they are a matching private CA.
func ParseAuthority(certPEM, keyPEM []byte) (Authority, error) {
	authority, err := ParseAuthorityCertificate(certPEM)
	if err != nil {
		return Authority{}, err
	}
	certificate := authority.Certificate
	privateKey, err := parseEd25519PrivateKey(keyPEM)
	if err != nil {
		return Authority{}, err
	}
	publicKey, ok := certificate.PublicKey.(ed25519.PublicKey)
	if !ok || !publicKey.Equal(privateKey.Public()) {
		return Authority{}, fmt.Errorf("controller CA certificate and key do not match")
	}
	authority.PrivateKey = privateKey
	authority.KeyPEM = append([]byte(nil), keyPEM...)
	return authority, nil
}

// IssueMachine creates separate controller-client and guest-server credentials
// bound to the exact machine ID.
func (authority Authority) IssueMachine(machineID string, now time.Time, validity time.Duration) (MachineBundle, error) {
	if err := validateMachineID(machineID); err != nil {
		return MachineBundle{}, err
	}
	if authority.Certificate == nil || len(authority.PrivateKey) != ed25519.PrivateKeySize {
		return MachineBundle{}, fmt.Errorf("complete controller CA authority is required")
	}
	if validity < time.Hour || validity > 5*365*24*time.Hour {
		return MachineBundle{}, fmt.Errorf("machine credential validity is outside 1 hour..5 years")
	}
	controller, err := authority.issue(RoleController, machineID, now, validity, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth})
	if err != nil {
		return MachineBundle{}, err
	}
	guest, err := authority.issue(RoleGuest, machineID, now, validity, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth})
	if err != nil {
		return MachineBundle{}, err
	}
	return MachineBundle{Controller: controller, Guest: guest}, nil
}

func (authority Authority) issue(role, machineID string, now time.Time, validity time.Duration, usages []x509.ExtKeyUsage) (Credentials, error) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return Credentials{}, fmt.Errorf("generate %s key: %w", role, err)
	}
	serial, err := randomSerial(rand.Reader)
	if err != nil {
		return Credentials{}, err
	}
	identity, err := IdentityURI(role, machineID)
	if err != nil {
		return Credentials{}, err
	}
	now = now.UTC()
	notAfter := now.Add(validity)
	if notAfter.After(authority.Certificate.NotAfter) {
		notAfter = authority.Certificate.NotAfter
	}
	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "EHJINT " + role + " " + machineID, Organization: []string{"StealthEye LLC"}},
		NotBefore:             now.Add(-5 * time.Minute),
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           usages,
		BasicConstraintsValid: true,
		IsCA:                  false,
		URIs:                  []*url.URL{identity},
		AuthorityKeyId:        authority.Certificate.SubjectKeyId,
		SubjectKeyId:          publicKey,
	}
	certificateDER, err := x509.CreateCertificate(rand.Reader, template, authority.Certificate, publicKey, authority.PrivateKey)
	if err != nil {
		return Credentials{}, fmt.Errorf("create %s certificate: %w", role, err)
	}
	certificate, err := x509.ParseCertificate(certificateDER)
	if err != nil {
		return Credentials{}, fmt.Errorf("parse generated %s certificate: %w", role, err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return Credentials{}, fmt.Errorf("marshal %s key: %w", role, err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificateDER})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	pair, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return Credentials{}, fmt.Errorf("load generated %s key pair: %w", role, err)
	}
	pair.Leaf = certificate
	return Credentials{Certificate: certificate, TLS: pair, CertPEM: certPEM, KeyPEM: keyPEM, Role: role, MachineID: machineID}, nil
}

// ParseCredentials verifies a leaf key pair, URI SAN, exact role, exact machine,
// and signing chain.
func ParseCredentials(certPEM, keyPEM []byte, role, machineID string, authority Authority, now time.Time) (Credentials, error) {
	if err := validateRole(role); err != nil {
		return Credentials{}, err
	}
	if err := validateMachineID(machineID); err != nil {
		return Credentials{}, err
	}
	pair, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return Credentials{}, fmt.Errorf("parse %s key pair: %w", role, err)
	}
	certificate, err := parseSingleCertificate(certPEM)
	if err != nil {
		return Credentials{}, err
	}
	pair.Leaf = certificate
	if err := verifyLeaf(certificate, pair.Certificate[1:], authority, role, machineID, now); err != nil {
		return Credentials{}, err
	}
	return Credentials{Certificate: certificate, TLS: pair, CertPEM: append([]byte(nil), certPEM...), KeyPEM: append([]byte(nil), keyPEM...), Role: role, MachineID: machineID}, nil
}

// ClientTLSConfig creates a TLS 1.3-only controller profile that independently
// verifies the guest chain and exact guest machine URI identity.
func ClientTLSConfig(machineID string, authority Authority, controller Credentials, clock func() time.Time) (*tls.Config, error) {
	if err := validateCredentialRole(controller, RoleController, machineID); err != nil {
		return nil, err
	}
	roots, err := rootPool(authority)
	if err != nil {
		return nil, err
	}
	if clock == nil {
		clock = time.Now
	}
	config := &tls.Config{
		MinVersion:             tls.VersionTLS13,
		MaxVersion:             tls.VersionTLS13,
		NextProtos:             []string{ALPN},
		Certificates:           []tls.Certificate{controller.TLS},
		RootCAs:                roots,
		InsecureSkipVerify:     true, // Replaced by the complete chain+URI verification below; there is no DNS name on AF_VSOCK.
		SessionTicketsDisabled: true,
		Time:                   clock,
		VerifyConnection: func(state tls.ConnectionState) error {
			if state.NegotiatedProtocol != ALPN {
				return fmt.Errorf("TLS ALPN mismatch: expected %s", ALPN)
			}
			if len(state.PeerCertificates) == 0 {
				return fmt.Errorf("guest presented no certificate")
			}
			return verifyLeaf(state.PeerCertificates[0], certificatesToDER(state.PeerCertificates[1:]), authority, RoleGuest, machineID, clock())
		},
	}
	return config, nil
}

// ServerTLSConfig creates a TLS 1.3-only guest profile that requires a CA-valid
// controller client certificate and exact controller machine URI identity.
func ServerTLSConfig(machineID string, authority Authority, guest Credentials, clock func() time.Time) (*tls.Config, error) {
	if err := validateCredentialRole(guest, RoleGuest, machineID); err != nil {
		return nil, err
	}
	roots, err := rootPool(authority)
	if err != nil {
		return nil, err
	}
	if clock == nil {
		clock = time.Now
	}
	config := &tls.Config{
		MinVersion:             tls.VersionTLS13,
		MaxVersion:             tls.VersionTLS13,
		NextProtos:             []string{ALPN},
		Certificates:           []tls.Certificate{guest.TLS},
		ClientCAs:              roots,
		ClientAuth:             tls.RequireAndVerifyClientCert,
		SessionTicketsDisabled: true,
		Time:                   clock,
		VerifyConnection: func(state tls.ConnectionState) error {
			if state.NegotiatedProtocol != ALPN {
				return fmt.Errorf("TLS ALPN mismatch: expected %s", ALPN)
			}
			if len(state.PeerCertificates) == 0 {
				return fmt.Errorf("controller presented no certificate")
			}
			return verifyIdentity(state.PeerCertificates[0], RoleController, machineID)
		},
	}
	return config, nil
}

// IdentityURI returns the only accepted leaf URI identity shape.
func IdentityURI(role, machineID string) (*url.URL, error) {
	if err := validateRole(role); err != nil {
		return nil, err
	}
	if err := validateMachineID(machineID); err != nil {
		return nil, err
	}
	return &url.URL{Scheme: identityScheme, Host: identityHost, Path: "/" + role + "/" + machineID}, nil
}

// WriteAuthority writes the controller CA through the common authoritative
// writer. The containing directory must already be a private real directory.
func WriteAuthority(root, directory string, authority Authority, owner atomicfile.Owner) error {
	if _, err := ParseAuthority(authority.CertPEM, authority.KeyPEM); err != nil {
		return fmt.Errorf("refuse invalid controller CA: %w", err)
	}
	if err := atomicfile.WriteVerified(root, filepath.Join(directory, "ca.crt"), authority.CertPEM, 0o644, owner, verifyCertificatePEM); err != nil {
		return err
	}
	if err := atomicfile.WriteVerified(root, filepath.Join(directory, "ca.key"), authority.KeyPEM, 0o600, owner, verifyPrivateKeyPEM); err != nil {
		return err
	}
	return nil
}

// WriteMachineBundle writes host and guest credentials to separate private
// directories. A caller copies only guest.crt, guest.key, and ca.crt into the
// guest seed.
func WriteMachineBundle(root, directory string, bundle MachineBundle, authority Authority, owner atomicfile.Owner) error {
	if _, err := ParseCredentials(bundle.Controller.CertPEM, bundle.Controller.KeyPEM, RoleController, bundle.Controller.MachineID, authority, time.Now()); err != nil {
		return fmt.Errorf("refuse invalid controller credentials: %w", err)
	}
	if _, err := ParseCredentials(bundle.Guest.CertPEM, bundle.Guest.KeyPEM, RoleGuest, bundle.Guest.MachineID, authority, time.Now()); err != nil {
		return fmt.Errorf("refuse invalid guest credentials: %w", err)
	}
	files := []struct {
		name   string
		data   []byte
		mode   os.FileMode
		verify atomicfile.Verifier
	}{
		{"controller.crt", bundle.Controller.CertPEM, 0o644, verifyCertificatePEM},
		{"controller.key", bundle.Controller.KeyPEM, 0o600, verifyPrivateKeyPEM},
		{"guest.crt", bundle.Guest.CertPEM, 0o644, verifyCertificatePEM},
		{"guest.key", bundle.Guest.KeyPEM, 0o600, verifyPrivateKeyPEM},
	}
	for _, file := range files {
		if err := atomicfile.WriteVerified(root, filepath.Join(directory, file.name), file.data, file.mode, owner, file.verify); err != nil {
			return err
		}
	}
	return nil
}

func verifyLeaf(certificate *x509.Certificate, intermediatesDER [][]byte, authority Authority, role, machineID string, now time.Time) error {
	roots, err := rootPool(authority)
	if err != nil {
		return err
	}
	intermediates := x509.NewCertPool()
	for _, encoded := range intermediatesDER {
		parsed, parseErr := x509.ParseCertificate(encoded)
		if parseErr != nil {
			return fmt.Errorf("parse presented intermediate: %w", parseErr)
		}
		intermediates.AddCert(parsed)
	}
	usage := x509.ExtKeyUsageClientAuth
	if role == RoleGuest {
		usage = x509.ExtKeyUsageServerAuth
	}
	if _, err := certificate.Verify(x509.VerifyOptions{Roots: roots, Intermediates: intermediates, CurrentTime: now.UTC(), KeyUsages: []x509.ExtKeyUsage{usage}}); err != nil {
		return fmt.Errorf("verify %s certificate chain: %w", role, err)
	}
	return verifyIdentity(certificate, role, machineID)
}

func verifyIdentity(certificate *x509.Certificate, role, machineID string) error {
	expected, err := IdentityURI(role, machineID)
	if err != nil {
		return err
	}
	if certificate.IsCA || len(certificate.URIs) != 1 || certificate.URIs[0].String() != expected.String() {
		return fmt.Errorf("certificate URI identity mismatch: expected %s", expected)
	}
	return nil
}

func validateCredentialRole(credentials Credentials, role, machineID string) error {
	if credentials.Certificate == nil || len(credentials.TLS.Certificate) == 0 || credentials.Role != role || credentials.MachineID != machineID {
		return fmt.Errorf("complete %s credentials for exact machine are required", role)
	}
	return verifyIdentity(credentials.Certificate, role, machineID)
}

func rootPool(authority Authority) (*x509.CertPool, error) {
	if authority.Certificate == nil || !authority.Certificate.IsCA {
		return nil, fmt.Errorf("valid controller CA certificate is required")
	}
	pool := x509.NewCertPool()
	pool.AddCert(authority.Certificate)
	return pool, nil
}

func randomSerial(reader io.Reader) (*big.Int, error) {
	bytes := make([]byte, 20)
	if _, err := io.ReadFull(reader, bytes); err != nil {
		return nil, fmt.Errorf("generate certificate serial: %w", err)
	}
	bytes[0] &= 0x7f
	if allZero(bytes) {
		bytes[len(bytes)-1] = 1
	}
	return new(big.Int).SetBytes(bytes), nil
}

func allZero(data []byte) bool {
	for _, value := range data {
		if value != 0 {
			return false
		}
	}
	return true
}

func validateMachineID(machineID string) error {
	if _, err := contracts.ParseIdentifier(contracts.MachineIDKind, machineID); err != nil {
		return fmt.Errorf("invalid machine ID: %w", err)
	}
	return nil
}

func validateRole(role string) error {
	if role != RoleController && role != RoleGuest {
		return fmt.Errorf("invalid TLS identity role %q", role)
	}
	return nil
}

func parseSingleCertificate(data []byte) (*x509.Certificate, error) {
	block, rest := pem.Decode(data)
	if block == nil || block.Type != "CERTIFICATE" || len(strings.TrimSpace(string(rest))) != 0 {
		return nil, fmt.Errorf("expected exactly one PEM certificate")
	}
	certificate, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse certificate: %w", err)
	}
	return certificate, nil
}

func parseEd25519PrivateKey(data []byte) (ed25519.PrivateKey, error) {
	block, rest := pem.Decode(data)
	if block == nil || block.Type != "PRIVATE KEY" || len(strings.TrimSpace(string(rest))) != 0 {
		return nil, fmt.Errorf("expected exactly one PKCS#8 PEM private key")
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse PKCS#8 private key: %w", err)
	}
	privateKey, ok := key.(ed25519.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("private key is not Ed25519")
	}
	return privateKey, nil
}

func verifyCertificatePEM(data []byte) error {
	_, err := parseSingleCertificate(data)
	return err
}

func verifyPrivateKeyPEM(data []byte) error {
	_, err := parseEd25519PrivateKey(data)
	return err
}

func certificatesToDER(certificates []*x509.Certificate) [][]byte {
	result := make([][]byte, 0, len(certificates))
	for _, certificate := range certificates {
		result = append(result, certificate.Raw)
	}
	return result
}
