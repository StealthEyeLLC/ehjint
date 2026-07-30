package contracts

import (
	"encoding/json"
	"fmt"
	"regexp"
)

// ErrorCode is a stable bounded machine-readable error code.
type ErrorCode string

const (
	CodeInvalidArgument     ErrorCode = "invalid_argument"
	CodeUnknownOperation    ErrorCode = "unknown_operation"
	CodeUnsupportedVersion  ErrorCode = "unsupported_version"
	CodeSchemaMismatch      ErrorCode = "schema_mismatch"
	CodeConflict            ErrorCode = "conflict"
	CodeIdempotencyConflict ErrorCode = "idempotency_conflict"
	CodeNotFound            ErrorCode = "not_found"
	CodeFailedPrecondition  ErrorCode = "failed_precondition"
	CodeUnavailable         ErrorCode = "unavailable"
	CodeTimeout             ErrorCode = "timeout"
	CodeCancelled           ErrorCode = "cancelled"
	CodeInternal            ErrorCode = "internal"
)

var validErrorCodes = map[ErrorCode]bool{
	CodeInvalidArgument: true, CodeUnknownOperation: true, CodeUnsupportedVersion: true,
	CodeSchemaMismatch: true, CodeConflict: true, CodeIdempotencyConflict: true,
	CodeNotFound: true, CodeFailedPrecondition: true, CodeUnavailable: true,
	CodeTimeout: true, CodeCancelled: true, CodeInternal: true,
}

var semanticOperationPattern = regexp.MustCompile(`^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)+$`)

// ErrorEnvelope is the public versioned error contract.
type ErrorEnvelope struct {
	SchemaVersion int            `json:"schema_version"`
	Code          ErrorCode      `json:"code"`
	Message       string         `json:"message"`
	Operation     string         `json:"operation"`
	OperationID   string         `json:"operation_id,omitempty"`
	Retryable     bool           `json:"retryable"`
	Details       map[string]any `json:"details,omitempty"`
}

// ResultEnvelope is the public versioned operation-result contract.
type ResultEnvelope struct {
	SchemaVersion    int             `json:"schema_version"`
	Operation        string          `json:"operation"`
	OperationVersion int             `json:"operation_version"`
	OperationID      string          `json:"operation_id,omitempty"`
	State            OperationState  `json:"state"`
	Result           json.RawMessage `json:"result,omitempty"`
	Error            *ErrorEnvelope  `json:"error,omitempty"`
}

// ValidateErrorEnvelope validates public shape without exposing internal stack data.
func ValidateErrorEnvelope(envelope ErrorEnvelope) error {
	if envelope.SchemaVersion != 1 {
		return fmt.Errorf("unsupported error envelope version %d", envelope.SchemaVersion)
	}
	if !validErrorCodes[envelope.Code] {
		return fmt.Errorf("invalid error code %q", envelope.Code)
	}
	if envelope.Message == "" || len(envelope.Message) > 1024 {
		return fmt.Errorf("error message must contain 1..1024 bytes")
	}
	if !semanticOperationPattern.MatchString(envelope.Operation) {
		return fmt.Errorf("invalid error operation %q", envelope.Operation)
	}
	if envelope.OperationID != "" {
		if _, err := ParseIdentifier(OperationIDKind, envelope.OperationID); err != nil {
			return err
		}
	}
	if envelope.Details != nil {
		data, err := json.Marshal(envelope.Details)
		if err != nil {
			return fmt.Errorf("encode error details: %w", err)
		}
		if len(data) > 16384 {
			return fmt.Errorf("error details exceed 16384 bytes")
		}
	}
	return nil
}

// ValidateResultEnvelope enforces mutually exclusive success and error payloads.
func ValidateResultEnvelope(envelope ResultEnvelope) error {
	if envelope.SchemaVersion != 1 {
		return fmt.Errorf("unsupported result envelope version %d", envelope.SchemaVersion)
	}
	if !semanticOperationPattern.MatchString(envelope.Operation) {
		return fmt.Errorf("invalid result operation %q", envelope.Operation)
	}
	if envelope.OperationVersion != 1 {
		return fmt.Errorf("unsupported operation version %d", envelope.OperationVersion)
	}
	if !ValidOperationState(envelope.State) {
		return fmt.Errorf("invalid result state %q", envelope.State)
	}
	if envelope.OperationID != "" {
		if _, err := ParseIdentifier(OperationIDKind, envelope.OperationID); err != nil {
			return err
		}
	}
	hasResult := len(envelope.Result) != 0
	hasError := envelope.Error != nil
	if hasResult && hasError {
		return fmt.Errorf("result and error cannot both be populated")
	}
	if envelope.State == StateSucceeded && (!hasResult || hasError) {
		return fmt.Errorf("succeeded result requires result and forbids error")
	}
	if (envelope.State == StateFailed || envelope.State == StateCancelled) && (!hasError || hasResult) {
		return fmt.Errorf("failed or cancelled result requires error and forbids result")
	}
	if (envelope.State == StateAccepted || envelope.State == StateRunning) && (hasResult || hasError) {
		return fmt.Errorf("accepted or running result forbids terminal payloads")
	}
	if envelope.Error != nil {
		if err := ValidateErrorEnvelope(*envelope.Error); err != nil {
			return err
		}
	}
	return nil
}

// ExitStatus maps stable public error codes to deterministic CLI statuses.
func ExitStatus(code ErrorCode) int {
	switch code {
	case CodeInvalidArgument:
		return 2
	case CodeUnknownOperation:
		return 3
	case CodeUnsupportedVersion, CodeSchemaMismatch:
		return 4
	case CodeFailedPrecondition:
		return 5
	case CodeConflict, CodeIdempotencyConflict:
		return 6
	case CodeNotFound:
		return 7
	case CodeUnavailable:
		return 8
	case CodeTimeout:
		return 9
	case CodeCancelled:
		return 130
	default:
		return 1
	}
}
