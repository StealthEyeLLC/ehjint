// Package controller implements EHJINT's authenticated local controller edge.
package controller

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"time"

	"github.com/StealthEyeLLC/ehjint/internal/contracts"
	"github.com/StealthEyeLLC/ehjint/internal/controlproto"
)

const (
	DefaultRequestTimeout = 30 * time.Second
	DefaultMaxConnections = 64
)

// Peer is independently observed local process identity. Groups includes the
// verified primary and supplementary groups from the same live process.
type Peer struct {
	PID           int
	UID           int
	GID           int
	Groups        []int
	StartIdentity string
}

// Handler receives one fully framed, validated, authorized request.
type Handler interface {
	Handle(context.Context, controlproto.Request, Peer, *Responder) error
}

// HandlerFunc adapts a function to Handler.
type HandlerFunc func(context.Context, controlproto.Request, Peer, *Responder) error

func (function HandlerFunc) Handle(ctx context.Context, request controlproto.Request, peer Peer, responder *Responder) error {
	return function(ctx, request, peer, responder)
}

// PublicError carries a safe error envelope across the local edge.
type PublicError struct {
	Envelope contracts.ErrorEnvelope
}

func (public *PublicError) Error() string   { return public.Envelope.Message }
func (public *PublicError) ExitStatus() int { return contracts.ExitStatus(public.Envelope.Code) }

// Result is the complete result observed by a thin client.
type Result struct {
	OperationID string
	Payload     json.RawMessage
	ExitStatus  *int
}

// Streams receives raw stream frames without interpreting terminal bytes.
type Streams struct {
	Stdout io.Writer
	Stderr io.Writer
}

func publicError(operation string, code contracts.ErrorCode, message string, retryable bool, operationID string) *PublicError {
	if len(message) > 1024 {
		message = message[:1024]
	}
	return &PublicError{Envelope: contracts.ErrorEnvelope{
		SchemaVersion: 1,
		Code:          code,
		Message:       message,
		Operation:     operation,
		OperationID:   operationID,
		Retryable:     retryable,
	}}
}

func deadlineFromRequest(now time.Time, request controlproto.Request) time.Time {
	if request.TimeoutMillis > 0 {
		return now.Add(time.Duration(request.TimeoutMillis) * time.Millisecond)
	}
	return now.Add(DefaultRequestTimeout)
}

func ensureWriter(writer io.Writer) io.Writer {
	if writer == nil {
		return io.Discard
	}
	return writer
}

func validateOperationName(operation string) error {
	if operation == "" {
		return fmt.Errorf("operation is required")
	}
	return nil
}
