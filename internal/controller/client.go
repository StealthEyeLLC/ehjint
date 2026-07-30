package controller

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"time"

	"github.com/StealthEyeLLC/ehjint/internal/controlproto"
	"github.com/StealthEyeLLC/ehjint/internal/framing"
)

// NewRequestID creates a bounded unpredictable transport correlation ID.
func NewRequestID() (string, error) {
	entropy := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, entropy); err != nil {
		return "", fmt.Errorf("read request ID entropy: %w", err)
	}
	return "request-" + hex.EncodeToString(entropy), nil
}

// Call performs exactly one local controller request with complete framing,
// global stream sequence checks, and a bounded deadline.
func Call(ctx context.Context, socketPath string, request controlproto.Request, streams Streams) (Result, error) {
	if ctx == nil {
		return Result{}, fmt.Errorf("controller call context is required")
	}
	if socketPath == "" {
		return Result{}, fmt.Errorf("controller socket path is required")
	}
	if err := controlproto.ValidateRequest(request); err != nil {
		return Result{}, err
	}
	deadline := deadlineFromRequest(time.Now(), request)
	if callerDeadline, ok := ctx.Deadline(); ok && callerDeadline.Before(deadline) {
		deadline = callerDeadline
	}
	dialer := net.Dialer{Timeout: time.Until(deadline)}
	connection, err := dialer.DialContext(ctx, "unix", socketPath)
	if err != nil {
		return Result{}, fmt.Errorf("connect to EHJINT controller: %w", err)
	}
	defer connection.Close()
	if err := connection.SetDeadline(deadline); err != nil {
		return Result{}, fmt.Errorf("set controller connection deadline: %w", err)
	}
	if err := framing.Write(connection, request, controlproto.MaxFrame); err != nil {
		return Result{}, fmt.Errorf("write controller request: %w", err)
	}
	stdout := ensureWriter(streams.Stdout)
	stderr := ensureWriter(streams.Stderr)
	var result Result
	var accepted bool
	var sequence uint64
	for {
		var response controlproto.Response
		if err := framing.Read(connection, &response, controlproto.MaxFrame); err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
				return Result{}, fmt.Errorf("controller closed before terminal response: %w", err)
			}
			return Result{}, fmt.Errorf("read controller response: %w", err)
		}
		if err := controlproto.ValidateResponse(response); err != nil {
			return Result{}, fmt.Errorf("validate controller response: %w", err)
		}
		if response.RequestID != request.RequestID {
			return Result{}, fmt.Errorf("controller response request ID mismatch")
		}
		if result.OperationID != "" && response.OperationID != "" && response.OperationID != result.OperationID {
			return Result{}, fmt.Errorf("controller response operation ID changed")
		}
		switch response.Kind {
		case "accepted":
			if accepted || result.OperationID != "" {
				return Result{}, fmt.Errorf("duplicate accepted response")
			}
			accepted = true
			result.OperationID = response.OperationID
		case "stream":
			if !accepted || response.Sequence != sequence+1 {
				return Result{}, fmt.Errorf("controller stream sequence mismatch: got %d want %d", response.Sequence, sequence+1)
			}
			sequence = response.Sequence
			writer := stdout
			if response.Stream == "stderr" {
				writer = stderr
			}
			if err := writeComplete(writer, response.Data); err != nil {
				return Result{}, fmt.Errorf("write controller %s stream: %w", response.Stream, err)
			}
		case "result":
			result.Payload = append(result.Payload[:0], response.Result...)
			return result, nil
		case "error":
			return Result{}, &PublicError{Envelope: *response.Error}
		case "end":
			if !accepted {
				return Result{}, fmt.Errorf("controller end arrived before accepted")
			}
			result.ExitStatus = response.ExitStatus
			return result, nil
		default:
			return Result{}, fmt.Errorf("unreachable controller response kind %q", response.Kind)
		}
	}
}

func writeComplete(writer io.Writer, data []byte) error {
	for len(data) > 0 {
		written, err := writer.Write(data)
		if err != nil {
			return err
		}
		if written <= 0 || written > len(data) {
			return io.ErrShortWrite
		}
		data = data[written:]
	}
	return nil
}
