// Package guestproto defines the strict, bounded, versioned EHJINT guest-agent
// protocol carried over mutually authenticated AF_VSOCK streams.
package guestproto

import (
	"encoding/json"
	"fmt"
	"path"
	"regexp"
	"sort"
	"strings"

	"github.com/StealthEyeLLC/ehjint/internal/contracts"
)

const (
	Version          = 1
	MaxFrame         = 1024 * 1024
	MaxData          = 64 * 1024
	MaxArguments     = 256
	MaxEnvironment   = 256
	MaxArgumentBytes = 64 * 1024
	MaxPathBytes     = 4096
	MaxMessageBytes  = 1024
)

const (
	KindHello        = "hello"
	KindHelloAck     = "hello_ack"
	KindPing         = "ping"
	KindPong         = "pong"
	KindExecStart    = "exec_start"
	KindStdin        = "stdin"
	KindStdinEOF     = "stdin_eof"
	KindResize       = "resize"
	KindSignal       = "signal"
	KindCancel       = "cancel"
	KindStdout       = "stdout"
	KindStderr       = "stderr"
	KindExit         = "exit"
	KindError        = "error"
	KindFilePutStart = "file_put_start"
	KindFileChunk    = "file_chunk"
	KindFilePutEnd   = "file_put_end"
	KindFileGet      = "file_get"
	KindFileInfo     = "file_info"
	KindFileData     = "file_data"
	KindFileEnd      = "file_end"
)

var (
	bootIDPattern = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	namePattern   = regexp.MustCompile(`^[a-z_][a-z0-9_-]{0,31}$`)
	envPattern    = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*=`)
	digestPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)
	noncePattern  = regexp.MustCompile(`^[0-9a-f]{32,128}$`)
)

// Frame is the only top-level wire shape. Payload is decoded strictly according
// to Kind, preventing loose maps and undeclared fields from crossing trust
// boundaries.
type Frame struct {
	ProtocolVersion int             `json:"protocol_version"`
	Kind            string          `json:"kind"`
	MachineID       string          `json:"machine_id"`
	OperationID     string          `json:"operation_id,omitempty"`
	Sequence        uint64          `json:"sequence,omitempty"`
	Payload         json.RawMessage `json:"payload"`
}

type Hello struct {
	AgentVersion       string `json:"agent_version"`
	GuestBootID        string `json:"guest_boot_id"`
	ManifestDigest     string `json:"manifest_digest"`
	SupportedProtocols []int  `json:"supported_protocols"`
}

type HelloAck struct {
	ControllerVersion string `json:"controller_version"`
	AcceptedProtocol  int    `json:"accepted_protocol"`
}

type Ping struct {
	Nonce string `json:"nonce"`
}

type Pong struct {
	Nonce       string `json:"nonce"`
	GuestBootID string `json:"guest_boot_id"`
}

type PTYSpec struct {
	Rows uint16 `json:"rows"`
	Cols uint16 `json:"cols"`
	Term string `json:"term"`
}

type ExecStart struct {
	Argv             []string `json:"argv"`
	Environment      []string `json:"environment"`
	WorkingDirectory string   `json:"working_directory"`
	User             string   `json:"user"`
	Group            string   `json:"group"`
	PTY              *PTYSpec `json:"pty,omitempty"`
	Stdin            bool     `json:"stdin"`
	TimeoutMillis    int64    `json:"timeout_millis"`
}

type Data struct {
	Data []byte `json:"data"`
}

type Empty struct{}

type Resize struct {
	Rows uint16 `json:"rows"`
	Cols uint16 `json:"cols"`
}

type Signal struct {
	Name string `json:"name"`
}

type Cancel struct {
	Reason string `json:"reason"`
}

type Exit struct {
	Status     int    `json:"status"`
	Signal     string `json:"signal,omitempty"`
	CoreDumped bool   `json:"core_dumped"`
}

type ProtocolError struct {
	Code      string `json:"code"`
	Message   string `json:"message"`
	Retryable bool   `json:"retryable"`
}

type FilePutStart struct {
	Path   string `json:"path"`
	Mode   uint32 `json:"mode"`
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
	User   string `json:"user"`
	Group  string `json:"group"`
}

type FileChunk struct {
	Offset int64  `json:"offset"`
	Data   []byte `json:"data"`
}

type FileGet struct {
	Path string `json:"path"`
}

type FileInfo struct {
	Mode   uint32 `json:"mode"`
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
}

type FileEnd struct {
	SHA256 string `json:"sha256"`
}

// NewFrame marshals a declared payload and immediately validates the result.
func NewFrame(kind, machineID, operationID string, sequence uint64, payload any) (Frame, error) {
	encoded, err := json.Marshal(payload)
	if err != nil {
		return Frame{}, fmt.Errorf("encode guest payload: %w", err)
	}
	frame := Frame{ProtocolVersion: Version, Kind: kind, MachineID: machineID, OperationID: operationID, Sequence: sequence, Payload: encoded}
	if err := ValidateFrame(frame); err != nil {
		return Frame{}, err
	}
	return frame, nil
}

// DecodePayload performs strict payload decoding for an already validated kind.
func DecodePayload(frame Frame, target any) error {
	if target == nil {
		return fmt.Errorf("payload target is required")
	}
	if len(frame.Payload) == 0 {
		return fmt.Errorf("guest payload is empty")
	}
	if err := contracts.DecodeStrict(frame.Payload, target); err != nil {
		return fmt.Errorf("decode %s payload: %w", frame.Kind, err)
	}
	return nil
}

// ValidateFrame enforces identifier, sequence, payload, and semantic bounds.
func ValidateFrame(frame Frame) error {
	if frame.ProtocolVersion != Version {
		return fmt.Errorf("unsupported guest protocol version %d", frame.ProtocolVersion)
	}
	if _, err := contracts.ParseIdentifier(contracts.MachineIDKind, frame.MachineID); err != nil {
		return fmt.Errorf("invalid guest frame machine ID: %w", err)
	}
	if len(frame.Payload) == 0 || len(frame.Payload) > MaxFrame/2 {
		return fmt.Errorf("guest payload is empty or exceeds bound")
	}
	operationRequired := false
	sequenceRequired := false
	switch frame.Kind {
	case KindHello:
		var value Hello
		if err := DecodePayload(frame, &value); err != nil {
			return err
		}
		if value.AgentVersion == "" || len(value.AgentVersion) > 128 || !bootIDPattern.MatchString(value.GuestBootID) || !digestPattern.MatchString(value.ManifestDigest) {
			return fmt.Errorf("invalid hello identity")
		}
		if len(value.SupportedProtocols) == 0 || len(value.SupportedProtocols) > 16 || !sort.IntsAreSorted(value.SupportedProtocols) {
			return fmt.Errorf("supported protocols must be a nonempty sorted set")
		}
		for index, version := range value.SupportedProtocols {
			if version < 1 || (index > 0 && value.SupportedProtocols[index-1] == version) {
				return fmt.Errorf("invalid or duplicate supported protocol")
			}
		}
	case KindHelloAck:
		var value HelloAck
		if err := DecodePayload(frame, &value); err != nil {
			return err
		}
		if value.ControllerVersion == "" || len(value.ControllerVersion) > 128 || value.AcceptedProtocol != Version {
			return fmt.Errorf("invalid hello acknowledgement")
		}
	case KindPing:
		var value Ping
		if err := DecodePayload(frame, &value); err != nil || !noncePattern.MatchString(value.Nonce) {
			return fmt.Errorf("invalid ping payload")
		}
	case KindPong:
		var value Pong
		if err := DecodePayload(frame, &value); err != nil || !noncePattern.MatchString(value.Nonce) || !bootIDPattern.MatchString(value.GuestBootID) {
			return fmt.Errorf("invalid pong payload")
		}
	case KindExecStart:
		operationRequired = true
		var value ExecStart
		if err := DecodePayload(frame, &value); err != nil {
			return err
		}
		if err := validateExec(value); err != nil {
			return err
		}
	case KindStdin, KindStdout, KindStderr:
		operationRequired, sequenceRequired = true, true
		var value Data
		if err := DecodePayload(frame, &value); err != nil {
			return err
		}
		if len(value.Data) == 0 || len(value.Data) > MaxData {
			return fmt.Errorf("stream data is empty or exceeds bound")
		}
	case KindStdinEOF:
		operationRequired, sequenceRequired = true, true
		var value Empty
		if err := DecodePayload(frame, &value); err != nil {
			return err
		}
	case KindResize:
		operationRequired, sequenceRequired = true, true
		var value Resize
		if err := DecodePayload(frame, &value); err != nil || value.Rows == 0 || value.Cols == 0 {
			return fmt.Errorf("invalid terminal resize")
		}
	case KindSignal:
		operationRequired, sequenceRequired = true, true
		var value Signal
		if err := DecodePayload(frame, &value); err != nil || !validSignal(value.Name) {
			return fmt.Errorf("invalid signal request")
		}
	case KindCancel:
		operationRequired, sequenceRequired = true, true
		var value Cancel
		if err := DecodePayload(frame, &value); err != nil || value.Reason == "" || len(value.Reason) > MaxMessageBytes {
			return fmt.Errorf("invalid cancellation request")
		}
	case KindExit:
		operationRequired, sequenceRequired = true, true
		var value Exit
		if err := DecodePayload(frame, &value); err != nil || value.Status < 0 || value.Status > 255 || (value.Signal != "" && !validSignal(value.Signal)) {
			return fmt.Errorf("invalid exit payload")
		}
	case KindError:
		operationRequired, sequenceRequired = true, true
		var value ProtocolError
		if err := DecodePayload(frame, &value); err != nil || !validErrorCode(value.Code) || value.Message == "" || len(value.Message) > MaxMessageBytes {
			return fmt.Errorf("invalid guest error payload")
		}
	case KindFilePutStart:
		operationRequired = true
		var value FilePutStart
		if err := DecodePayload(frame, &value); err != nil || validateGuestPath(value.Path) != nil || value.Mode > 0o777 || value.Mode&0o002 != 0 || value.Size < 0 || !digestPattern.MatchString(value.SHA256) || !namePattern.MatchString(value.User) || !namePattern.MatchString(value.Group) {
			return fmt.Errorf("invalid file put metadata")
		}
	case KindFileChunk, KindFileData:
		operationRequired, sequenceRequired = true, true
		var value FileChunk
		if err := DecodePayload(frame, &value); err != nil || value.Offset < 0 || len(value.Data) == 0 || len(value.Data) > MaxData {
			return fmt.Errorf("invalid file data payload")
		}
	case KindFilePutEnd:
		operationRequired, sequenceRequired = true, true
		var value Empty
		if err := DecodePayload(frame, &value); err != nil {
			return err
		}
	case KindFileGet:
		operationRequired = true
		var value FileGet
		if err := DecodePayload(frame, &value); err != nil || validateGuestPath(value.Path) != nil {
			return fmt.Errorf("invalid file get payload")
		}
	case KindFileInfo:
		operationRequired, sequenceRequired = true, true
		var value FileInfo
		if err := DecodePayload(frame, &value); err != nil || value.Mode > 0o777 || value.Size < 0 || !digestPattern.MatchString(value.SHA256) {
			return fmt.Errorf("invalid file information payload")
		}
	case KindFileEnd:
		operationRequired, sequenceRequired = true, true
		var value FileEnd
		if err := DecodePayload(frame, &value); err != nil || !digestPattern.MatchString(value.SHA256) {
			return fmt.Errorf("invalid file end payload")
		}
	default:
		return fmt.Errorf("unknown guest frame kind %q", frame.Kind)
	}
	if operationRequired {
		if _, err := contracts.ParseIdentifier(contracts.OperationIDKind, frame.OperationID); err != nil {
			return fmt.Errorf("invalid guest frame operation ID: %w", err)
		}
	} else if frame.OperationID != "" {
		return fmt.Errorf("guest frame kind %q forbids operation ID", frame.Kind)
	}
	if sequenceRequired {
		if frame.Sequence == 0 {
			return fmt.Errorf("guest frame kind %q requires a positive sequence", frame.Kind)
		}
	} else if frame.Sequence != 0 {
		return fmt.Errorf("guest frame kind %q forbids sequence", frame.Kind)
	}
	return nil
}

func validateExec(value ExecStart) error {
	if len(value.Argv) == 0 || len(value.Argv) > MaxArguments {
		return fmt.Errorf("exec argv must contain 1..%d elements", MaxArguments)
	}
	total := 0
	for _, argument := range value.Argv {
		if argument == "" || strings.ContainsRune(argument, '\x00') || len(argument) > MaxPathBytes {
			return fmt.Errorf("invalid exec argument")
		}
		total += len(argument)
	}
	if total > MaxArgumentBytes {
		return fmt.Errorf("exec argv exceeds total byte bound")
	}
	if len(value.Environment) > MaxEnvironment {
		return fmt.Errorf("exec environment exceeds count bound")
	}
	seen := make(map[string]bool, len(value.Environment))
	for _, variable := range value.Environment {
		if strings.ContainsRune(variable, '\x00') || !envPattern.MatchString(variable) || len(variable) > MaxPathBytes {
			return fmt.Errorf("invalid exec environment entry")
		}
		key := strings.SplitN(variable, "=", 2)[0]
		if seen[key] {
			return fmt.Errorf("duplicate exec environment key %q", key)
		}
		seen[key] = true
		total += len(variable)
	}
	if total > 2*MaxArgumentBytes {
		return fmt.Errorf("exec request exceeds total byte bound")
	}
	if err := validateGuestPath(value.WorkingDirectory); err != nil {
		return fmt.Errorf("invalid exec working directory: %w", err)
	}
	if !namePattern.MatchString(value.User) || !namePattern.MatchString(value.Group) {
		return fmt.Errorf("invalid exec user or group")
	}
	if value.TimeoutMillis < 0 || value.TimeoutMillis > 24*60*60*1000 {
		return fmt.Errorf("invalid exec timeout")
	}
	if value.PTY != nil {
		if value.PTY.Rows == 0 || value.PTY.Cols == 0 || value.PTY.Term == "" || len(value.PTY.Term) > 64 || strings.ContainsRune(value.PTY.Term, '\x00') {
			return fmt.Errorf("invalid PTY request")
		}
	}
	return nil
}

func validateGuestPath(value string) error {
	if value == "" || len(value) > MaxPathBytes || strings.ContainsRune(value, '\x00') || !strings.HasPrefix(value, "/") || path.Clean(value) != value {
		return fmt.Errorf("guest path must be canonical absolute path")
	}
	return nil
}

func validSignal(value string) bool {
	switch value {
	case "SIGHUP", "SIGINT", "SIGQUIT", "SIGTERM", "SIGKILL", "SIGUSR1", "SIGUSR2", "SIGWINCH":
		return true
	default:
		return false
	}
}

func validErrorCode(value string) bool {
	switch value {
	case "invalid_request", "not_found", "permission_denied", "conflict", "unavailable", "timeout", "cancelled", "exec_failed", "io_failed", "internal":
		return true
	default:
		return false
	}
}
