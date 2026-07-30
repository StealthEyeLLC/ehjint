package guestproto

import (
	"encoding/json"
	"strings"
	"testing"
)

const (
	testMachine   = "mach_aebagbafaydqqcikbmga2dqpca"
	testOperation = "op_aebagbafaydqqcikbmga2dqpca"
	testBoot      = "01234567-89ab-cdef-0123-456789abcdef"
)

func mustPayload(t *testing.T, value any) json.RawMessage {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func TestValidHandshakeAndExecVocabulary(t *testing.T) {
	frames := []Frame{
		{ProtocolVersion: Version, Kind: KindHello, MachineID: testMachine, Payload: mustPayload(t, Hello{AgentVersion: "0.1.0", GuestBootID: testBoot, ManifestDigest: strings.Repeat("a", 64), SupportedProtocols: []int{1}})},
		{ProtocolVersion: Version, Kind: KindHelloAck, MachineID: testMachine, Payload: mustPayload(t, HelloAck{ControllerVersion: "0.1.0", AcceptedProtocol: 1})},
		{ProtocolVersion: Version, Kind: KindPing, MachineID: testMachine, Payload: mustPayload(t, Ping{Nonce: strings.Repeat("b", 32)})},
		{ProtocolVersion: Version, Kind: KindPong, MachineID: testMachine, Payload: mustPayload(t, Pong{Nonce: strings.Repeat("b", 32), GuestBootID: testBoot})},
		{ProtocolVersion: Version, Kind: KindExecStart, MachineID: testMachine, OperationID: testOperation, Payload: mustPayload(t, ExecStart{Argv: []string{"/usr/bin/printf", "%s", "exact"}, Environment: []string{"LANG=C.UTF-8"}, WorkingDirectory: "/tmp", User: "root", Group: "root", Stdin: true, TimeoutMillis: 1000})},
		{ProtocolVersion: Version, Kind: KindStdin, MachineID: testMachine, OperationID: testOperation, Sequence: 1, Payload: mustPayload(t, Data{Data: []byte("input")})},
		{ProtocolVersion: Version, Kind: KindStdinEOF, MachineID: testMachine, OperationID: testOperation, Sequence: 2, Payload: mustPayload(t, Empty{})},
		{ProtocolVersion: Version, Kind: KindStdout, MachineID: testMachine, OperationID: testOperation, Sequence: 1, Payload: mustPayload(t, Data{Data: []byte("output")})},
		{ProtocolVersion: Version, Kind: KindExit, MachineID: testMachine, OperationID: testOperation, Sequence: 2, Payload: mustPayload(t, Exit{Status: 37})},
	}
	for index, frame := range frames {
		if err := ValidateFrame(frame); err != nil {
			t.Fatalf("frame %d (%s) rejected: %v", index, frame.Kind, err)
		}
	}
}

func TestValidPTYAndFileVocabulary(t *testing.T) {
	frames := []Frame{
		{ProtocolVersion: Version, Kind: KindExecStart, MachineID: testMachine, OperationID: testOperation, Payload: mustPayload(t, ExecStart{Argv: []string{"/bin/sh"}, WorkingDirectory: "/", User: "root", Group: "root", PTY: &PTYSpec{Rows: 24, Cols: 80, Term: "xterm-256color"}})},
		{ProtocolVersion: Version, Kind: KindResize, MachineID: testMachine, OperationID: testOperation, Sequence: 1, Payload: mustPayload(t, Resize{Rows: 40, Cols: 120})},
		{ProtocolVersion: Version, Kind: KindSignal, MachineID: testMachine, OperationID: testOperation, Sequence: 2, Payload: mustPayload(t, Signal{Name: "SIGINT"})},
		{ProtocolVersion: Version, Kind: KindCancel, MachineID: testMachine, OperationID: testOperation, Sequence: 3, Payload: mustPayload(t, Cancel{Reason: "operator cancellation"})},
		{ProtocolVersion: Version, Kind: KindFilePutStart, MachineID: testMachine, OperationID: testOperation, Payload: mustPayload(t, FilePutStart{Path: "/tmp/file", Mode: 0o640, Size: 4, SHA256: strings.Repeat("c", 64), User: "root", Group: "root"})},
		{ProtocolVersion: Version, Kind: KindFileChunk, MachineID: testMachine, OperationID: testOperation, Sequence: 1, Payload: mustPayload(t, FileChunk{Offset: 0, Data: []byte("data")})},
		{ProtocolVersion: Version, Kind: KindFilePutEnd, MachineID: testMachine, OperationID: testOperation, Sequence: 2, Payload: mustPayload(t, Empty{})},
		{ProtocolVersion: Version, Kind: KindFileGet, MachineID: testMachine, OperationID: testOperation, Payload: mustPayload(t, FileGet{Path: "/tmp/file"})},
		{ProtocolVersion: Version, Kind: KindFileInfo, MachineID: testMachine, OperationID: testOperation, Sequence: 1, Payload: mustPayload(t, FileInfo{Mode: 0o640, Size: 4, SHA256: strings.Repeat("c", 64)})},
		{ProtocolVersion: Version, Kind: KindFileData, MachineID: testMachine, OperationID: testOperation, Sequence: 2, Payload: mustPayload(t, FileChunk{Offset: 0, Data: []byte("data")})},
		{ProtocolVersion: Version, Kind: KindFileEnd, MachineID: testMachine, OperationID: testOperation, Sequence: 3, Payload: mustPayload(t, FileEnd{SHA256: strings.Repeat("c", 64)})},
	}
	for index, frame := range frames {
		if err := ValidateFrame(frame); err != nil {
			t.Fatalf("frame %d (%s) rejected: %v", index, frame.Kind, err)
		}
	}
}

func TestRejectsUnknownFieldsBoundsAndContradictions(t *testing.T) {
	base := Frame{ProtocolVersion: Version, Kind: KindExecStart, MachineID: testMachine, OperationID: testOperation}
	invalid := []Frame{
		{ProtocolVersion: 2, Kind: KindPing, MachineID: testMachine, Payload: mustPayload(t, Ping{Nonce: strings.Repeat("a", 32)})},
		{ProtocolVersion: Version, Kind: KindPing, MachineID: "not-a-machine", Payload: mustPayload(t, Ping{Nonce: strings.Repeat("a", 32)})},
		{ProtocolVersion: Version, Kind: KindHello, MachineID: testMachine, OperationID: testOperation, Payload: mustPayload(t, Hello{AgentVersion: "x", GuestBootID: testBoot, ManifestDigest: strings.Repeat("a", 64), SupportedProtocols: []int{1}})},
		{ProtocolVersion: Version, Kind: KindStdin, MachineID: testMachine, OperationID: testOperation, Payload: mustPayload(t, Data{Data: []byte("x")})},
		{ProtocolVersion: Version, Kind: KindStdout, MachineID: testMachine, OperationID: testOperation, Sequence: 1, Payload: mustPayload(t, Data{Data: []byte(strings.Repeat("x", MaxData+1))})},
		{ProtocolVersion: Version, Kind: "invented", MachineID: testMachine, Payload: mustPayload(t, Empty{})},
	}
	unknown := base
	unknown.Payload = json.RawMessage(`{"argv":["/bin/true"],"environment":[],"working_directory":"/","user":"root","group":"root","stdin":false,"timeout_millis":0,"extra":true}`)
	invalid = append(invalid, unknown)
	for index, frame := range invalid {
		if err := ValidateFrame(frame); err == nil {
			t.Fatalf("invalid frame %d accepted: %+v", index, frame)
		}
	}
}

func TestRejectsShellShortcutAndUnsafeExecInputs(t *testing.T) {
	valid := ExecStart{Argv: []string{"/bin/echo", "literal ; rm -rf /"}, WorkingDirectory: "/", User: "root", Group: "root"}
	frame, err := NewFrame(KindExecStart, testMachine, testOperation, 0, valid)
	if err != nil || len(frame.Payload) == 0 {
		t.Fatalf("literal argv rejected: %+v %v", frame, err)
	}
	cases := []ExecStart{
		{Argv: nil, WorkingDirectory: "/", User: "root", Group: "root"},
		{Argv: []string{""}, WorkingDirectory: "/", User: "root", Group: "root"},
		{Argv: []string{"/bin/true"}, Environment: []string{"BAD"}, WorkingDirectory: "/", User: "root", Group: "root"},
		{Argv: []string{"/bin/true"}, Environment: []string{"A=1", "A=2"}, WorkingDirectory: "/", User: "root", Group: "root"},
		{Argv: []string{"/bin/true"}, WorkingDirectory: "/tmp/../etc", User: "root", Group: "root"},
		{Argv: []string{"/bin/true"}, WorkingDirectory: "/", User: "Root", Group: "root"},
		{Argv: []string{"/bin/true"}, WorkingDirectory: "/", User: "root", Group: "root", TimeoutMillis: 24*60*60*1000 + 1},
	}
	for index, value := range cases {
		frame := Frame{ProtocolVersion: Version, Kind: KindExecStart, MachineID: testMachine, OperationID: testOperation, Payload: mustPayload(t, value)}
		if err := ValidateFrame(frame); err == nil {
			t.Fatalf("unsafe exec case %d accepted", index)
		}
	}
}

func TestExitAcceptsKernelSignalTruthBeyondControlSubset(t *testing.T) {
	frame, err := NewFrame(KindExit, "mach_aaaaaaaaaaaaaaaaaaaaaaaaaa", "op_aaaaaaaaaaaaaaaaaaaaaaaaaa", 1, Exit{Status: 139, Signal: "SIGSEGV", CoreDumped: true})
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateFrame(frame); err != nil {
		t.Fatalf("valid signal exit rejected: %v", err)
	}
	if _, err := NewFrame(KindExit, "mach_aaaaaaaaaaaaaaaaaaaaaaaaaa", "op_aaaaaaaaaaaaaaaaaaaaaaaaaa", 1, Exit{Status: 1, Signal: "SIGMADEUP"}); err == nil {
		t.Fatal("invented exit signal accepted")
	}
}
