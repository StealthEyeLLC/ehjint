package contracts

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
)

var idempotencyKeyPattern = regexp.MustCompile(`^[A-Za-z0-9._:-]{8,128}$`)

// IdempotencyRecord is the minimal durable semantic record Mission 2 will persist.
type IdempotencyRecord struct {
	Key           string `json:"key"`
	RequestDigest string `json:"request_digest"`
	OperationID   string `json:"operation_id"`
}

// IdempotencyDecision does not create storage or claim durable authority.
type IdempotencyDecision string

const (
	IdempotencyCreate IdempotencyDecision = "create"
	IdempotencyReplay IdempotencyDecision = "replay"
)

// ValidateIdempotencyKey enforces a filename- and URL-safe bounded key.
func ValidateIdempotencyKey(key string) error {
	if !idempotencyKeyPattern.MatchString(key) {
		return fmt.Errorf("invalid idempotency key")
	}
	return nil
}

// RequestDigest binds the semantic operation, compatibility version, and canonical input.
func RequestDigest(operation string, operationVersion int, input []byte) (string, error) {
	if !semanticOperationPattern.MatchString(operation) {
		return "", fmt.Errorf("invalid operation name %q", operation)
	}
	if operationVersion != 1 {
		return "", fmt.Errorf("unsupported operation version %d", operationVersion)
	}
	canonicalInput, err := CanonicalJSON(input)
	if err != nil {
		return "", err
	}
	var decoded any
	decoder := json.NewDecoder(bytes.NewReader(canonicalInput))
	decoder.UseNumber()
	if err := decoder.Decode(&decoded); err != nil {
		return "", fmt.Errorf("decode canonical request input: %w", err)
	}
	request := struct {
		Input            any    `json:"input"`
		Operation        string `json:"operation"`
		OperationVersion int    `json:"operation_version"`
	}{Input: decoded, Operation: operation, OperationVersion: operationVersion}
	canonical, err := json.Marshal(request)
	if err != nil {
		return "", fmt.Errorf("encode canonical request: %w", err)
	}
	digest := sha256.Sum256(canonical)
	return hex.EncodeToString(digest[:]), nil
}

// EvaluateIdempotency distinguishes creation, replay, and conflicting key reuse.
func EvaluateIdempotency(existing *IdempotencyRecord, key, requestDigest, candidateOperationID string) (IdempotencyDecision, string, *ErrorEnvelope) {
	if err := ValidateIdempotencyKey(key); err != nil {
		return "", "", &ErrorEnvelope{SchemaVersion: 1, Code: CodeInvalidArgument, Message: err.Error(), Operation: "system.idempotency", Retryable: false}
	}
	if len(requestDigest) != 64 {
		return "", "", &ErrorEnvelope{SchemaVersion: 1, Code: CodeInvalidArgument, Message: "request digest must be 64 lowercase hexadecimal characters", Operation: "system.idempotency", Retryable: false}
	}
	if _, err := hex.DecodeString(requestDigest); err != nil || requestDigest != strings.ToLower(requestDigest) {
		return "", "", &ErrorEnvelope{SchemaVersion: 1, Code: CodeInvalidArgument, Message: "request digest must be 64 lowercase hexadecimal characters", Operation: "system.idempotency", Retryable: false}
	}
	if existing == nil {
		if _, err := ParseIdentifier(OperationIDKind, candidateOperationID); err != nil {
			return "", "", &ErrorEnvelope{SchemaVersion: 1, Code: CodeInvalidArgument, Message: err.Error(), Operation: "system.idempotency", Retryable: false}
		}
		return IdempotencyCreate, candidateOperationID, nil
	}
	if existing.Key != key {
		return "", "", &ErrorEnvelope{SchemaVersion: 1, Code: CodeInternal, Message: "idempotency lookup returned a mismatched key", Operation: "system.idempotency", Retryable: false}
	}
	if _, err := ParseIdentifier(OperationIDKind, existing.OperationID); err != nil || len(existing.RequestDigest) != 64 || existing.RequestDigest != strings.ToLower(existing.RequestDigest) {
		return "", "", &ErrorEnvelope{SchemaVersion: 1, Code: CodeInternal, Message: "idempotency lookup returned a corrupt record", Operation: "system.idempotency", Retryable: false}
	}
	if _, err := hex.DecodeString(existing.RequestDigest); err != nil {
		return "", "", &ErrorEnvelope{SchemaVersion: 1, Code: CodeInternal, Message: "idempotency lookup returned a corrupt record", Operation: "system.idempotency", Retryable: false}
	}
	if existing.RequestDigest == requestDigest {
		return IdempotencyReplay, existing.OperationID, nil
	}
	return "", "", &ErrorEnvelope{
		SchemaVersion: 1,
		Code:          CodeIdempotencyConflict,
		Message:       "idempotency key was already bound to a different canonical request",
		Operation:     "system.idempotency",
		OperationID:   existing.OperationID,
		Retryable:     false,
	}
}
