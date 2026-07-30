// Package controlproto defines the strict framed local controller protocol.
package controlproto

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"

	"github.com/StealthEyeLLC/ehjint/internal/contracts"
)

const (
	Version          = 1
	MaxFrame         = 1024 * 1024
	MaxStreamPayload = 64 * 1024
)

var (
	requestIDPattern = regexp.MustCompile(`^request-[a-z0-9][a-z0-9-]{5,119}$`)
	operationPattern = regexp.MustCompile(`^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)+$`)
)

// Request is one controller operation. Input remains strict operation-specific
// JSON and is validated again against the canonical registry before dispatch.
type Request struct {
	ProtocolVersion  int             `json:"protocol_version"`
	RequestID        string          `json:"request_id"`
	Operation        string          `json:"operation"`
	OperationVersion int             `json:"operation_version"`
	IdempotencyKey   string          `json:"idempotency_key,omitempty"`
	Invocation       string          `json:"invocation,omitempty"`
	TimeoutMillis    int64           `json:"timeout_millis,omitempty"`
	Input            json.RawMessage `json:"input"`
}

// Response is one bounded response frame. A request may receive accepted,
// stream, result/error, and end frames in that order.
type Response struct {
	ProtocolVersion int                      `json:"protocol_version"`
	RequestID       string                   `json:"request_id"`
	Kind            string                   `json:"kind"`
	OperationID     string                   `json:"operation_id,omitempty"`
	Sequence        uint64                   `json:"sequence,omitempty"`
	Stream          string                   `json:"stream,omitempty"`
	Data            []byte                   `json:"data,omitempty"`
	Result          json.RawMessage          `json:"result,omitempty"`
	Error           *contracts.ErrorEnvelope `json:"error,omitempty"`
	ExitStatus      *int                     `json:"exit_status,omitempty"`
}

// ValidateRequest enforces transport-level invariants before semantic schema
// validation.
func ValidateRequest(request Request) error {
	if request.ProtocolVersion != Version {
		return fmt.Errorf("unsupported controller protocol version %d", request.ProtocolVersion)
	}
	if !requestIDPattern.MatchString(request.RequestID) {
		return fmt.Errorf("invalid request ID")
	}
	if !operationPattern.MatchString(request.Operation) {
		return fmt.Errorf("invalid operation name")
	}
	if request.OperationVersion < 1 {
		return fmt.Errorf("operation version must be positive")
	}
	if len(request.IdempotencyKey) > 256 || strings.ContainsRune(request.IdempotencyKey, '\x00') {
		return fmt.Errorf("invalid idempotency key")
	}
	if len(request.Invocation) > 4096 || strings.ContainsRune(request.Invocation, '\x00') {
		return fmt.Errorf("invalid invocation")
	}
	if request.TimeoutMillis < 0 || request.TimeoutMillis > 24*60*60*1000 {
		return fmt.Errorf("invalid request timeout")
	}
	if len(request.Input) == 0 || len(request.Input) > MaxFrame/2 {
		return fmt.Errorf("input is empty or exceeds bound")
	}
	var object map[string]json.RawMessage
	if err := contracts.DecodeStrict(request.Input, &object); err != nil {
		return fmt.Errorf("input must be one strict JSON object: %w", err)
	}
	if object == nil {
		return fmt.Errorf("input must be a JSON object")
	}
	return nil
}

// Digest returns the canonical operation request digest used by durable
// idempotency. Request and idempotency IDs are deliberately excluded.
func Digest(request Request) (string, error) {
	if err := ValidateRequest(request); err != nil {
		return "", err
	}
	canonicalInput, err := contracts.CanonicalJSON(request.Input)
	if err != nil {
		return "", fmt.Errorf("canonicalize controller input: %w", err)
	}
	identity := struct {
		Operation        string          `json:"operation"`
		OperationVersion int             `json:"operation_version"`
		TimeoutMillis    int64           `json:"timeout_millis,omitempty"`
		Input            json.RawMessage `json:"input"`
	}{request.Operation, request.OperationVersion, request.TimeoutMillis, canonicalInput}
	encoded, err := json.Marshal(identity)
	if err != nil {
		return "", fmt.Errorf("encode controller request identity: %w", err)
	}
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:]), nil
}

// ValidateResponse rejects contradictory response fields.
func ValidateResponse(response Response) error {
	if response.ProtocolVersion != Version || !requestIDPattern.MatchString(response.RequestID) {
		return fmt.Errorf("invalid controller response protocol or request ID")
	}
	if response.OperationID != "" {
		if _, err := contracts.ParseIdentifier(contracts.OperationIDKind, response.OperationID); err != nil {
			return fmt.Errorf("invalid operation ID: %w", err)
		}
	}
	if len(response.Data) > MaxStreamPayload {
		return fmt.Errorf("stream payload exceeds bound")
	}
	switch response.Kind {
	case "accepted":
		if response.OperationID == "" || response.Sequence != 0 || response.Stream != "" || len(response.Data) != 0 || len(response.Result) != 0 || response.Error != nil || response.ExitStatus != nil {
			return fmt.Errorf("contradictory accepted response")
		}
	case "stream":
		if response.OperationID == "" || response.Sequence == 0 || (response.Stream != "stdout" && response.Stream != "stderr") || len(response.Result) != 0 || response.Error != nil || response.ExitStatus != nil {
			return fmt.Errorf("contradictory stream response")
		}
	case "result":
		if response.Sequence != 0 || response.Stream != "" || len(response.Data) != 0 || len(response.Result) == 0 || response.Error != nil || response.ExitStatus != nil {
			return fmt.Errorf("contradictory result response")
		}
		var value any
		if err := contracts.DecodeStrict(response.Result, &value); err != nil {
			return fmt.Errorf("invalid result JSON: %w", err)
		}
	case "error":
		if response.Sequence != 0 || response.Stream != "" || len(response.Data) != 0 || len(response.Result) != 0 || response.Error == nil || response.ExitStatus != nil {
			return fmt.Errorf("contradictory error response")
		}
		if err := contracts.ValidateErrorEnvelope(*response.Error); err != nil {
			return fmt.Errorf("invalid error envelope: %w", err)
		}
	case "end":
		if response.OperationID == "" || response.Sequence != 0 || response.Stream != "" || len(response.Data) != 0 || len(response.Result) != 0 || response.Error != nil || response.ExitStatus == nil || *response.ExitStatus < 0 || *response.ExitStatus > 255 {
			return fmt.Errorf("contradictory end response")
		}
	default:
		return fmt.Errorf("unknown controller response kind %q", response.Kind)
	}
	return nil
}
