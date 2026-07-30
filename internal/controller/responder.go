package controller

import (
	"encoding/json"
	"fmt"
	"sync"

	"github.com/StealthEyeLLC/ehjint/internal/contracts"
	"github.com/StealthEyeLLC/ehjint/internal/controlproto"
	"github.com/StealthEyeLLC/ehjint/internal/framing"
)

// Responder serializes complete bounded response frames and prevents any frame
// after a terminal result, error, or end.
type Responder struct {
	requestID   string
	operationID string
	writer      frameWriter
	mu          sync.Mutex
	sequence    uint64
	terminal    bool
	accepted    bool
}

type frameWriter interface {
	WriteFrame(controlproto.Response) error
}

type connectionFrameWriter struct {
	writer interface{ Write([]byte) (int, error) }
}

func (writer connectionFrameWriter) WriteFrame(response controlproto.Response) error {
	if err := controlproto.ValidateResponse(response); err != nil {
		return err
	}
	return framing.Write(writer.writer, response, controlproto.MaxFrame)
}

func newResponder(requestID string, writer frameWriter) *Responder {
	return &Responder{requestID: requestID, writer: writer}
}

// Accepted records the durable operation identity before any stream/mutation.
func (responder *Responder) Accepted(operationID string) error {
	responder.mu.Lock()
	defer responder.mu.Unlock()
	if responder.terminal || responder.accepted {
		return fmt.Errorf("accepted response is out of order")
	}
	response := controlproto.Response{ProtocolVersion: controlproto.Version, RequestID: responder.requestID, Kind: "accepted", OperationID: operationID}
	if err := responder.writer.WriteFrame(response); err != nil {
		return err
	}
	responder.operationID = operationID
	responder.accepted = true
	return nil
}

// Stream sends one complete raw stream chunk in global sequence order.
func (responder *Responder) Stream(stream string, data []byte) error {
	responder.mu.Lock()
	defer responder.mu.Unlock()
	if responder.terminal || !responder.accepted || len(data) == 0 {
		return fmt.Errorf("stream response is out of order or empty")
	}
	responder.sequence++
	response := controlproto.Response{ProtocolVersion: controlproto.Version, RequestID: responder.requestID, Kind: "stream", OperationID: responder.operationID, Sequence: responder.sequence, Stream: stream, Data: append([]byte(nil), data...)}
	return responder.writer.WriteFrame(response)
}

// Result emits one strict JSON terminal result for non-streaming operations.
func (responder *Responder) Result(value any) error {
	responder.mu.Lock()
	defer responder.mu.Unlock()
	if responder.terminal {
		return fmt.Errorf("terminal response already sent")
	}
	payload, err := json.Marshal(value)
	if err != nil {
		return fmt.Errorf("marshal controller result: %w", err)
	}
	response := controlproto.Response{ProtocolVersion: controlproto.Version, RequestID: responder.requestID, Kind: "result", OperationID: responder.operationID, Result: payload}
	if err := responder.writer.WriteFrame(response); err != nil {
		return err
	}
	responder.terminal = true
	return nil
}

// Error emits one safe terminal error envelope.
func (responder *Responder) Error(envelope contracts.ErrorEnvelope) error {
	responder.mu.Lock()
	defer responder.mu.Unlock()
	if responder.terminal {
		return fmt.Errorf("terminal response already sent")
	}
	if envelope.OperationID == "" {
		envelope.OperationID = responder.operationID
	}
	response := controlproto.Response{ProtocolVersion: controlproto.Version, RequestID: responder.requestID, Kind: "error", OperationID: responder.operationID, Error: &envelope}
	if err := responder.writer.WriteFrame(response); err != nil {
		return err
	}
	responder.terminal = true
	return nil
}

// End closes a streaming operation with exact guest/command exit status.
func (responder *Responder) End(exitStatus int) error {
	responder.mu.Lock()
	defer responder.mu.Unlock()
	if responder.terminal || !responder.accepted {
		return fmt.Errorf("end response is out of order")
	}
	response := controlproto.Response{ProtocolVersion: controlproto.Version, RequestID: responder.requestID, Kind: "end", OperationID: responder.operationID, ExitStatus: &exitStatus}
	if err := responder.writer.WriteFrame(response); err != nil {
		return err
	}
	responder.terminal = true
	return nil
}

func (responder *Responder) isTerminal() bool {
	responder.mu.Lock()
	defer responder.mu.Unlock()
	return responder.terminal
}
