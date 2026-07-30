package pki

import (
	"context"
	"crypto/tls"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/StealthEyeLLC/ehjint/internal/atomicfile"
)

const (
	machineOne = "mach_aebagbafaydqqcikbmga2dqpca"
	machineTwo = "mach_aibqibiga4eascqlbqgq4dyqce"
)

var fixedNow = time.Date(2026, 7, 30, 12, 0, 0, 0, time.UTC)

func makePKI(t *testing.T, machineID string) (Authority, MachineBundle) {
	t.Helper()
	authority, err := GenerateAuthority(fixedNow, 10*365*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	bundle, err := authority.IssueMachine(machineID, fixedNow, 365*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	return authority, bundle
}

func TestAuthorityAndCredentialsRoundTrip(t *testing.T) {
	authority, bundle := makePKI(t, machineOne)
	parsedAuthority, err := ParseAuthority(authority.CertPEM, authority.KeyPEM)
	if err != nil {
		t.Fatal(err)
	}
	controller, err := ParseCredentials(bundle.Controller.CertPEM, bundle.Controller.KeyPEM, RoleController, machineOne, parsedAuthority, fixedNow)
	if err != nil {
		t.Fatal(err)
	}
	guest, err := ParseCredentials(bundle.Guest.CertPEM, bundle.Guest.KeyPEM, RoleGuest, machineOne, parsedAuthority, fixedNow)
	if err != nil {
		t.Fatal(err)
	}
	if controller.Certificate.URIs[0].String() != "spiffe://ehjint.local/controller/"+machineOne || guest.Certificate.URIs[0].String() != "spiffe://ehjint.local/guest/"+machineOne {
		t.Fatalf("unexpected identities: %v %v", controller.Certificate.URIs, guest.Certificate.URIs)
	}
	if _, err := ParseCredentials(bundle.Guest.CertPEM, bundle.Guest.KeyPEM, RoleController, machineOne, parsedAuthority, fixedNow); err == nil {
		t.Fatal("guest credential accepted as controller")
	}
	if _, err := ParseCredentials(bundle.Controller.CertPEM, bundle.Controller.KeyPEM, RoleController, machineTwo, parsedAuthority, fixedNow); err == nil {
		t.Fatal("controller credential accepted for another machine")
	}
	if _, err := ParseCredentials(bundle.Controller.CertPEM, bundle.Guest.KeyPEM, RoleController, machineOne, parsedAuthority, fixedNow); err == nil {
		t.Fatal("mismatched key pair accepted")
	}
}

func TestMutualTLSHandshakeAndCrossMachineRejection(t *testing.T) {
	authority, one := makePKI(t, machineOne)
	two, err := authority.IssueMachine(machineTwo, fixedNow, 365*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	clock := func() time.Time { return fixedNow }
	clientOne, err := ClientTLSConfig(machineOne, authority, one.Controller, clock)
	if err != nil {
		t.Fatal(err)
	}
	serverOne, err := ServerTLSConfig(machineOne, authority, one.Guest, clock)
	if err != nil {
		t.Fatal(err)
	}
	if err := handshake(clientOne, serverOne); err != nil {
		t.Fatalf("exact mutual TLS handshake failed: %v", err)
	}
	clientTwo, err := ClientTLSConfig(machineTwo, authority, two.Controller, clock)
	if err != nil {
		t.Fatal(err)
	}
	if err := handshake(clientTwo, serverOne); err == nil {
		t.Fatal("cross-machine controller credential completed handshake")
	}
	serverTwo, err := ServerTLSConfig(machineTwo, authority, two.Guest, clock)
	if err != nil {
		t.Fatal(err)
	}
	if err := handshake(clientOne, serverTwo); err == nil {
		t.Fatal("cross-machine guest credential completed handshake")
	}
}

func TestExpiredCredentialAndForeignAuthorityRejected(t *testing.T) {
	authority, bundle := makePKI(t, machineOne)
	foreign, _ := makePKI(t, machineOne)
	if _, err := ParseCredentials(bundle.Guest.CertPEM, bundle.Guest.KeyPEM, RoleGuest, machineOne, authority, fixedNow.Add(2*365*24*time.Hour)); err == nil {
		t.Fatal("expired credential accepted")
	}
	if _, err := ParseCredentials(bundle.Guest.CertPEM, bundle.Guest.KeyPEM, RoleGuest, machineOne, foreign, fixedNow); err == nil {
		t.Fatal("foreign authority accepted")
	}
}

func TestAuthoritativeCredentialFilesHaveExactModes(t *testing.T) {
	authority, bundle := makePKI(t, machineOne)
	root := t.TempDir()
	caDir := filepath.Join(root, "pki")
	machineDir := filepath.Join(root, "machines", machineOne, "pki")
	for _, directory := range []string{caDir, filepath.Dir(filepath.Dir(machineDir)), filepath.Dir(machineDir), machineDir} {
		if err := os.Mkdir(directory, 0o700); err != nil && !os.IsExist(err) {
			t.Fatal(err)
		}
	}
	owner := atomicfile.Owner{UID: os.Getuid(), GID: os.Getgid()}
	if err := WriteAuthority(root, caDir, authority, owner); err != nil {
		t.Fatal(err)
	}
	if err := WriteMachineBundle(root, machineDir, bundle, authority, owner); err != nil {
		t.Fatal(err)
	}
	for file, expected := range map[string]os.FileMode{
		filepath.Join(caDir, "ca.crt"):              0o644,
		filepath.Join(caDir, "ca.key"):              0o600,
		filepath.Join(machineDir, "controller.crt"): 0o644,
		filepath.Join(machineDir, "controller.key"): 0o600,
		filepath.Join(machineDir, "guest.crt"):      0o644,
		filepath.Join(machineDir, "guest.key"):      0o600,
	} {
		info, err := os.Stat(file)
		if err != nil || info.Mode().Perm() != expected {
			t.Fatalf("%s mode = %v err=%v expected=%04o", file, info, err, expected)
		}
	}
}

func handshake(clientConfig, serverConfig *tls.Config) error {
	clientRaw, serverRaw := net.Pipe()
	defer clientRaw.Close()
	defer serverRaw.Close()
	client := tls.Client(clientRaw, clientConfig)
	server := tls.Server(serverRaw, serverConfig)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	clientResult := make(chan error, 1)
	serverResult := make(chan error, 1)
	go func() { clientResult <- client.HandshakeContext(ctx) }()
	go func() { serverResult <- server.HandshakeContext(ctx) }()
	clientErr := <-clientResult
	serverErr := <-serverResult
	if clientErr != nil {
		return clientErr
	}
	return serverErr
}

func TestPublicAuthoritySupportsTLSButCannotIssue(t *testing.T) {
	now := time.Date(2026, 7, 30, 12, 0, 0, 0, time.UTC)
	authority, err := GenerateAuthority(now, 365*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	public, err := ParseAuthorityCertificate(authority.CertPEM)
	if err != nil {
		t.Fatal(err)
	}
	if public.Certificate == nil || len(public.PrivateKey) != 0 || len(public.KeyPEM) != 0 {
		t.Fatal("public authority retained or invented private material")
	}
	if _, err := public.IssueMachine("mach_aaaaaaaaaaaaaaaaaaaaaaaaaa", now, 24*time.Hour); err == nil {
		t.Fatal("public authority issued credentials")
	}
}
