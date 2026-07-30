package guestagent_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/StealthEyeLLC/ehjint/internal/contracts"
	"github.com/StealthEyeLLC/ehjint/internal/guestagent"
	"github.com/StealthEyeLLC/ehjint/internal/guestbuild"
	"github.com/StealthEyeLLC/ehjint/internal/guestproto"
	"github.com/StealthEyeLLC/ehjint/internal/guestsession"
	"github.com/StealthEyeLLC/ehjint/internal/pki"
)

const testBootID = "11111111-1111-4111-8111-111111111111"

type harness struct {
	server       *guestagent.Server
	client       guestsession.Client
	authority    pki.Authority
	machineID    string
	manifest     string
	controller   pki.Credentials
	serverErrors chan error
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	now := time.Now().UTC().Add(-time.Minute)
	identifier, err := contracts.NewIdentifierFrom(contracts.MachineIDKind, bytes.NewReader(make([]byte, 16)))
	if err != nil {
		t.Fatal(err)
	}
	authority, err := pki.GenerateAuthority(now, 365*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	bundle, err := authority.IssueMachine(identifier.String(), now, 90*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	publicAuthority, err := pki.ParseAuthorityCertificate(authority.CertPEM)
	if err != nil {
		t.Fatal(err)
	}
	guestCredentials, err := pki.ParseCredentials(bundle.Guest.CertPEM, bundle.Guest.KeyPEM, pki.RoleGuest, identifier.String(), publicAuthority, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	manifest := strings.Repeat("a", 64)
	document := guestbuild.GuestConfig{
		SchemaVersion: 1, MachineID: identifier.String(), ManifestDigest: manifest,
		AgentVersion: "0.0.0-dev", ProtocolVersion: guestproto.Version, VsockPort: 19000,
		CACertificatePath: "/etc/ehjint/pki/ca.crt", CertificatePath: "/etc/ehjint/pki/guest.crt", PrivateKeyPath: "/etc/ehjint/pki/guest.key",
		GuestCertificateSHA256: certificateDigest(guestCredentials.Certificate.Raw),
		CACertificateSHA256:    certificateDigest(publicAuthority.Certificate.Raw),
	}
	server, err := guestagent.NewServer(guestagent.RuntimeConfig{Document: document, Authority: publicAuthority, Credentials: guestCredentials}, testBootID)
	if err != nil {
		t.Fatal(err)
	}
	clientTLS, err := pki.ClientTLSConfig(identifier.String(), authority, bundle.Controller, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	return &harness{
		server:    server,
		client:    guestsession.Client{MachineID: identifier.String(), ManifestDigest: manifest, ControllerVersion: "test-controller", TLSConfig: clientTLS},
		authority: authority, machineID: identifier.String(), manifest: manifest, controller: bundle.Controller,
		serverErrors: make(chan error, 32),
	}
}

func (harness *harness) connect(t *testing.T) *guestsession.Session {
	t.Helper()
	controller, guest := net.Pipe()
	go func() { harness.serverErrors <- harness.server.ServeConn(guest) }()
	session, err := harness.client.Dial(controller)
	if err != nil {
		_ = controller.Close()
		t.Fatal(err)
	}
	if session.BootID() != testBootID {
		t.Fatalf("boot ID = %q", session.BootID())
	}
	return session
}

func operationID(t *testing.T, fill byte) string {
	t.Helper()
	identifier, err := contracts.NewIdentifierFrom(contracts.OperationIDKind, bytes.NewReader(bytes.Repeat([]byte{fill}, 16)))
	if err != nil {
		t.Fatal(err)
	}
	return identifier.String()
}

type collected struct {
	stdout  bytes.Buffer
	stderr  bytes.Buffer
	exit    *guestproto.Exit
	failure *guestproto.ProtocolError
}

func collect(t *testing.T, execution *guestsession.Execution) collected {
	t.Helper()
	var result collected
	for {
		frame, err := execution.Read()
		if err != nil {
			t.Fatal(err)
		}
		switch frame.Kind {
		case guestproto.KindStdout:
			var data guestproto.Data
			if err := guestproto.DecodePayload(frame, &data); err != nil {
				t.Fatal(err)
			}
			result.stdout.Write(data.Data)
		case guestproto.KindStderr:
			var data guestproto.Data
			if err := guestproto.DecodePayload(frame, &data); err != nil {
				t.Fatal(err)
			}
			result.stderr.Write(data.Data)
		case guestproto.KindExit:
			var exit guestproto.Exit
			if err := guestproto.DecodePayload(frame, &exit); err != nil {
				t.Fatal(err)
			}
			result.exit = &exit
			return result
		case guestproto.KindError:
			var failure guestproto.ProtocolError
			if err := guestproto.DecodePayload(frame, &failure); err != nil {
				t.Fatal(err)
			}
			result.failure = &failure
			return result
		default:
			t.Fatalf("unexpected execution frame %q", frame.Kind)
		}
	}
}

func rootRequest(argv ...string) guestproto.ExecStart {
	return guestproto.ExecStart{Argv: argv, WorkingDirectory: "/", User: "root", Group: "root"}
}

func TestAuthenticatedLiteralRootExecution(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("root credential test requires UID 0")
	}
	harness := newHarness(t)
	session := harness.connect(t)
	defer session.Close()
	if err := session.Ping(strings.Repeat("a", 32)); err != nil {
		t.Fatal(err)
	}
	execution, err := session.Start(operationID(t, 1), rootRequest("sh", "-c", "printf out; printf err >&2; exit 37"))
	if err != nil {
		t.Fatal(err)
	}
	result := collect(t, execution)
	if result.failure != nil || result.exit == nil || result.exit.Status != 37 || result.exit.Signal != "" || result.stdout.String() != "out" || result.stderr.String() != "err" {
		t.Fatalf("unexpected execution: exit=%+v failure=%+v stdout=%q stderr=%q", result.exit, result.failure, result.stdout.String(), result.stderr.String())
	}

	identity, err := session.Start(operationID(t, 2), rootRequest("sh", "-c", "printf '%s:%s:%s:%s' \"$(id -u)\" \"$(id -g)\" \"$(id -G)\" \"$PWD\""))
	if err != nil {
		t.Fatal(err)
	}
	identityResult := collect(t, identity)
	if identityResult.exit == nil || identityResult.exit.Status != 0 || identityResult.stdout.String() != "0:0:0:/" {
		t.Fatalf("root identity = %q exit=%+v failure=%+v", identityResult.stdout.String(), identityResult.exit, identityResult.failure)
	}
}

func TestStdinEnvironmentAndLiteralArguments(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("root credential test requires UID 0")
	}
	harness := newHarness(t)
	session := harness.connect(t)
	defer session.Close()
	request := rootRequest("sh", "-c", "IFS= read -r value; printf '%s|%s|%s' \"$value\" \"$EHJINT_TEST\" \"$1\"", "sh", "literal argument with spaces")
	request.Stdin = true
	request.Environment = []string{"EHJINT_TEST=exact environment"}
	execution, err := session.Start(operationID(t, 10), request)
	if err != nil {
		t.Fatal(err)
	}
	if err := execution.Stdin([]byte("exact stdin\n")); err != nil {
		t.Fatal(err)
	}
	if err := execution.StdinEOF(); err != nil {
		t.Fatal(err)
	}
	result := collect(t, execution)
	if result.failure != nil || result.exit == nil || result.exit.Status != 0 || result.stdout.String() != "exact stdin|exact environment|literal argument with spaces" || result.stderr.Len() != 0 {
		t.Fatalf("stdin/environment result: exit=%+v failure=%+v stdout=%q stderr=%q", result.exit, result.failure, result.stdout.String(), result.stderr.String())
	}
}

func TestSignalTimeoutAndCancellationTruth(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("root credential test requires UID 0")
	}
	harness := newHarness(t)
	session := harness.connect(t)
	defer session.Close()

	signaled, err := session.Start(operationID(t, 3), rootRequest("sh", "-c", "kill -TERM $$"))
	if err != nil {
		t.Fatal(err)
	}
	signalResult := collect(t, signaled)
	if signalResult.exit == nil || signalResult.exit.Signal != "SIGTERM" || signalResult.exit.Status != 143 {
		t.Fatalf("signal truth = exit=%+v failure=%+v", signalResult.exit, signalResult.failure)
	}

	timedRequest := rootRequest("sleep", "30")
	timedRequest.TimeoutMillis = 100
	timed, err := session.Start(operationID(t, 4), timedRequest)
	if err != nil {
		t.Fatal(err)
	}
	timedResult := collect(t, timed)
	if timedResult.failure == nil || timedResult.failure.Code != "timeout" {
		t.Fatalf("timeout truth = %+v exit=%+v", timedResult.failure, timedResult.exit)
	}

	cancelled, err := session.Start(operationID(t, 5), rootRequest("sleep", "30"))
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(50 * time.Millisecond)
	if err := cancelled.Cancel("test cancellation"); err != nil {
		t.Fatal(err)
	}
	cancelResult := collect(t, cancelled)
	if cancelResult.failure == nil || cancelResult.failure.Code != "cancelled" {
		t.Fatalf("cancel truth = %+v exit=%+v", cancelResult.failure, cancelResult.exit)
	}
}

func TestForegroundPTYAndResize(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("root credential test requires UID 0")
	}
	harness := newHarness(t)
	session := harness.connect(t)
	defer session.Close()
	request := rootRequest("sh", "-c", "stty size; printf pty-ok")
	request.PTY = &guestproto.PTYSpec{Rows: 33, Cols: 77, Term: "xterm-256color"}
	execution, err := session.Start(operationID(t, 6), request)
	if err != nil {
		t.Fatal(err)
	}
	if err := execution.Resize(34, 78); err != nil {
		t.Fatal(err)
	}
	result := collect(t, execution)
	if result.failure != nil || result.exit == nil || result.exit.Status != 0 || !strings.Contains(result.stdout.String(), "34 78") || !strings.Contains(result.stdout.String(), "pty-ok") {
		t.Fatalf("PTY result: exit=%+v failure=%+v stdout=%q", result.exit, result.failure, result.stdout.String())
	}
}

func TestOperationContinuesAndReplaysAfterControllerDisconnect(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("root credential test requires UID 0")
	}
	harness := newHarness(t)
	path := filepath.Join(t.TempDir(), "runs")
	request := rootRequest("sh", "-c", fmt.Sprintf("printf run >> %q; sleep 0.2; printf replay", path))
	id := operationID(t, 7)
	firstSession := harness.connect(t)
	if _, err := firstSession.Start(id, request); err != nil {
		t.Fatal(err)
	}
	time.Sleep(50 * time.Millisecond)
	_ = firstSession.Close()

	secondSession := harness.connect(t)
	defer secondSession.Close()
	reconnected, err := secondSession.Start(id, request)
	if err != nil {
		t.Fatal(err)
	}
	result := collect(t, reconnected)
	if result.exit == nil || result.exit.Status != 0 || result.stdout.String() != "replay" {
		t.Fatalf("replay result: exit=%+v failure=%+v stdout=%q", result.exit, result.failure, result.stdout.String())
	}
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(content) != "run" {
		t.Fatalf("operation executed more than once: %q", content)
	}

	thirdSession := harness.connect(t)
	defer thirdSession.Close()
	completedReplay, err := thirdSession.Start(id, request)
	if err != nil {
		t.Fatal(err)
	}
	thirdResult := collect(t, completedReplay)
	if thirdResult.stdout.String() != "replay" || thirdResult.exit == nil || thirdResult.exit.Status != 0 {
		t.Fatalf("completed replay failed: %+v %q", thirdResult.exit, thirdResult.stdout.String())
	}
	content, err = os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(content) != "run" {
		t.Fatalf("completed replay executed again: %q", content)
	}
}

func TestConflictingReplayAndWrongIdentityFailClosed(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("root credential test requires UID 0")
	}
	harness := newHarness(t)
	id := operationID(t, 8)
	session := harness.connect(t)
	first, err := session.Start(id, rootRequest("printf", "one"))
	if err != nil {
		t.Fatal(err)
	}
	firstResult := collect(t, first)
	if firstResult.exit == nil || firstResult.stdout.String() != "one" {
		t.Fatalf("first execution failed: %+v %q", firstResult.exit, firstResult.stdout.String())
	}
	_ = session.Close()

	conflictSession := harness.connect(t)
	defer conflictSession.Close()
	conflict, err := conflictSession.Start(id, rootRequest("printf", "two"))
	if err != nil {
		t.Fatal(err)
	}
	conflictResult := collect(t, conflict)
	if conflictResult.failure == nil || conflictResult.failure.Code != "conflict" {
		t.Fatalf("conflicting replay accepted: %+v", conflictResult)
	}

	controller, guest := net.Pipe()
	go func() { harness.serverErrors <- harness.server.ServeConn(guest) }()
	badClient := harness.client
	badClient.ManifestDigest = strings.Repeat("b", 64)
	if session, err := badClient.Dial(controller); err == nil {
		_ = session.Close()
		t.Fatal("wrong manifest identity was accepted")
	}
}

func TestCrossMachineTLSIsRejected(t *testing.T) {
	harness := newHarness(t)
	otherID, err := contracts.NewIdentifierFrom(contracts.MachineIDKind, bytes.NewReader(bytes.Repeat([]byte{9}, 16)))
	if err != nil {
		t.Fatal(err)
	}
	otherBundle, err := harness.authority.IssueMachine(otherID.String(), time.Now().Add(-time.Minute), 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	otherTLS, err := pki.ClientTLSConfig(otherID.String(), harness.authority, otherBundle.Controller, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	controller, guest := net.Pipe()
	go func() { harness.serverErrors <- harness.server.ServeConn(guest) }()
	client := guestsession.Client{MachineID: otherID.String(), ManifestDigest: harness.manifest, ControllerVersion: "wrong-machine", TLSConfig: otherTLS}
	if session, err := client.Dial(controller); err == nil {
		_ = session.Close()
		t.Fatal("cross-machine TLS identity was accepted")
	}
}

func certificateDigest(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}
