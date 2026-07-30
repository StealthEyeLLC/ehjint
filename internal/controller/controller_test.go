package controller

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/StealthEyeLLC/ehjint/internal/contracts"
	"github.com/StealthEyeLLC/ehjint/internal/controlproto"
	"github.com/StealthEyeLLC/ehjint/internal/layout"
)

const testOperationID = "op_aebagbafaydqqcikbmga2dqpca"

func testRequest(t *testing.T, operation string) controlproto.Request {
	t.Helper()
	requestID, err := NewRequestID()
	if err != nil {
		t.Fatal(err)
	}
	return controlproto.Request{ProtocolVersion: controlproto.Version, RequestID: requestID, Operation: operation, OperationVersion: 1, Invocation: "ehjint " + operation, TimeoutMillis: 5000, Input: json.RawMessage(`{"value":"exact"}`)}
}

func startTestServer(t *testing.T, handler Handler) (layout.Paths, context.CancelFunc, <-chan error) {
	t.Helper()
	root := t.TempDir()
	paths := layout.UnderRoot(root)
	server, err := NewServer(ServerConfig{
		Paths: paths, SocketUID: os.Getuid(), SocketGID: os.Getgid(),
		Policy:  Policy{GroupID: os.Getgid(), RootOnly: map[string]bool{"system.remove": true}},
		Handler: handler,
		ValidateOperation: func(operation string, version int) error {
			if version != 1 || (operation != "system.version" && operation != "exec.run") {
				return errors.New("unknown")
			}
			return nil
		},
		RequestTimeout: 5 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- server.ListenAndServe(ctx) }()
	for deadline := time.Now().Add(3 * time.Second); ; {
		info, statErr := os.Stat(paths.ControllerSocket)
		if statErr == nil && info.Mode()&os.ModeSocket != 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("controller socket did not appear: %v", statErr)
		}
		time.Sleep(10 * time.Millisecond)
	}
	return paths, cancel, done
}

func TestServerClientRoundTripAndStreamOrder(t *testing.T) {
	handler := HandlerFunc(func(_ context.Context, request controlproto.Request, peer Peer, responder *Responder) error {
		if peer.PID <= 0 || peer.UID != os.Getuid() {
			return errors.New("bad peer")
		}
		if request.Operation == "system.version" {
			return responder.Result(map[string]any{"ok": true})
		}
		if err := responder.Accepted(testOperationID); err != nil {
			return err
		}
		if err := responder.Stream("stdout", []byte("one")); err != nil {
			return err
		}
		if err := responder.Stream("stderr", []byte("two")); err != nil {
			return err
		}
		return responder.End(37)
	})
	paths, cancel, done := startTestServer(t, handler)
	defer func() {
		cancel()
		if err := <-done; err != nil {
			t.Errorf("server: %v", err)
		}
	}()

	result, err := Call(context.Background(), paths.ControllerSocket, testRequest(t, "system.version"), Streams{})
	if err != nil || string(result.Payload) != `{"ok":true}` {
		t.Fatalf("result=%s err=%v", result.Payload, err)
	}
	var stdout, stderr bytes.Buffer
	result, err = Call(context.Background(), paths.ControllerSocket, testRequest(t, "exec.run"), Streams{Stdout: &stdout, Stderr: &stderr})
	if err != nil || result.OperationID != testOperationID || result.ExitStatus == nil || *result.ExitStatus != 37 || stdout.String() != "one" || stderr.String() != "two" {
		t.Fatalf("stream result=%+v stdout=%q stderr=%q err=%v", result, stdout.String(), stderr.String(), err)
	}
}

func TestSingletonAndSocketModes(t *testing.T) {
	root := t.TempDir()
	paths := layout.UnderRoot(root)
	config := ServerConfig{Paths: paths, SocketUID: os.Getuid(), SocketGID: os.Getgid(), Policy: Policy{GroupID: os.Getgid()}, Handler: HandlerFunc(func(context.Context, controlproto.Request, Peer, *Responder) error { return nil }), ValidateOperation: func(string, int) error { return nil }}
	first, err := NewServer(config)
	if err != nil {
		t.Fatal(err)
	}
	if err := first.acquire(); err != nil {
		t.Fatal(err)
	}
	defer first.release()
	info, err := os.Stat(paths.ControllerSocket)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o660 {
		t.Fatalf("socket mode=%04o", info.Mode().Perm())
	}
	second, err := NewServer(config)
	if err != nil {
		t.Fatal(err)
	}
	if err := second.acquire(); err == nil {
		second.release()
		t.Fatal("second controller acquired singleton")
	}
}

func TestPolicyRequiresVerifiedGroupAndRootForRootOnly(t *testing.T) {
	policy := Policy{GroupID: 42, RootOnly: map[string]bool{"system.remove": true}}
	if err := policy.Authorize(Peer{UID: 1000, GID: 1000, Groups: []int{42, 1000}}, "system.version"); err != nil {
		t.Fatal(err)
	}
	if err := policy.Authorize(Peer{UID: 1000, GID: 42, Groups: []int{1000}}, "system.version"); err == nil {
		t.Fatal("unverified primary group accepted")
	}
	if err := policy.Authorize(Peer{UID: 1000, GID: 42, Groups: []int{42}}, "system.remove"); err == nil {
		t.Fatal("non-root destructive operation accepted")
	}
	if err := policy.Authorize(Peer{UID: 0}, "system.remove"); err != nil {
		t.Fatal(err)
	}
}

func TestParsePeerStatusRejectsCredentialMismatch(t *testing.T) {
	status := []byte("Uid:\t1000\t1000\t1000\t1000\nGid:\t1001\t1001\t1001\t1001\nGroups:\t1001 42\n")
	stat := []byte("123 (command with spaces) S 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 777 21")
	peer, err := parsePeerStatus(123, 1000, 1001, status, stat)
	if err != nil || peer.StartIdentity != "777" || !strings.Contains(strings.TrimSpace(strings.Join([]string{"42"}, "")), "42") {
		t.Fatalf("peer=%+v err=%v", peer, err)
	}
	if _, err := parsePeerStatus(123, 999, 1001, status, stat); err == nil {
		t.Fatal("UID mismatch accepted")
	}
}

type oneByteWriter struct{ bytes.Buffer }

func (writer *oneByteWriter) Write(data []byte) (int, error) {
	if len(data) > 1 {
		data = data[:1]
	}
	return writer.Buffer.Write(data)
}

func TestWriteCompleteHandlesShortWrites(t *testing.T) {
	var writer oneByteWriter
	if err := writeComplete(&writer, []byte("complete")); err != nil {
		t.Fatal(err)
	}
	if writer.String() != "complete" {
		t.Fatalf("written=%q", writer.String())
	}
	if err := writeComplete(io.Discard, nil); err != nil {
		t.Fatal(err)
	}
}

func TestSecureDirectoryRejectsSymlinkAndWorldWritable(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	link := filepath.Join(root, "run")
	if err := os.Symlink(outside, link); err != nil {
		t.Fatal(err)
	}
	if err := secureDirectory(root, filepath.Join(link, "ehjint"), 0o750, os.Getuid(), os.Getgid()); err == nil {
		t.Fatal("symlink component accepted")
	}
	if err := os.Remove(link); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(link, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(link, 0o777); err != nil {
		t.Fatal(err)
	}
	if err := secureDirectory(root, filepath.Join(link, "ehjint"), 0o750, os.Getuid(), os.Getgid()); err == nil {
		t.Fatal("world-writable component accepted")
	}
}

func TestPublicErrorExitStatus(t *testing.T) {
	err := publicError("exec.run", contracts.CodeCancelled, "cancelled", false, testOperationID)
	if err.ExitStatus() != contracts.ExitStatus(contracts.CodeCancelled) {
		t.Fatalf("status=%d", err.ExitStatus())
	}
}
