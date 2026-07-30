// Package guestsession implements the authenticated host side of EHJINT's
// guest protocol. It is transport-agnostic after a connected byte stream is
// supplied, allowing the same code to use Cloud Hypervisor's vsock backend and
// deterministic in-memory tests.
package guestsession

import (
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/StealthEyeLLC/ehjint/internal/framing"
	"github.com/StealthEyeLLC/ehjint/internal/guestproto"
)

const handshakeTimeout = 15 * time.Second

// Client binds the expected guest identity and protocol contract.
type Client struct {
	MachineID         string
	ManifestDigest    string
	ControllerVersion string
	TLSConfig         *tls.Config
}

// Session is one authenticated controller-to-guest connection. Mission 2
// permits one foreground execution at a time per session.
type Session struct {
	connection net.Conn
	machineID  string
	bootID     string
	writeMu    sync.Mutex
	activeMu   sync.Mutex
	active     bool
}

// Dial authenticates one already-connected transport and verifies the guest's
// exact machine, manifest, protocol, and boot identity before acknowledging it.
func (client Client) Dial(raw net.Conn) (*Session, error) {
	if raw == nil || client.TLSConfig == nil || client.MachineID == "" || client.ManifestDigest == "" || client.ControllerVersion == "" {
		return nil, fmt.Errorf("complete guest client identity is required")
	}
	if err := raw.SetDeadline(time.Now().Add(handshakeTimeout)); err != nil {
		return nil, fmt.Errorf("set controller handshake deadline: %w", err)
	}
	secure := tls.Client(raw, client.TLSConfig.Clone())
	if err := secure.Handshake(); err != nil {
		_ = raw.Close()
		return nil, fmt.Errorf("authenticate guest: %w", err)
	}
	var frame guestproto.Frame
	if err := framing.Read(secure, &frame, guestproto.MaxFrame); err != nil {
		_ = secure.Close()
		return nil, fmt.Errorf("read guest hello: %w", err)
	}
	if err := guestproto.ValidateFrame(frame); err != nil {
		_ = secure.Close()
		return nil, fmt.Errorf("validate guest hello: %w", err)
	}
	if frame.Kind != guestproto.KindHello || frame.MachineID != client.MachineID {
		_ = secure.Close()
		return nil, fmt.Errorf("guest hello machine identity mismatch")
	}
	var hello guestproto.Hello
	if err := guestproto.DecodePayload(frame, &hello); err != nil {
		_ = secure.Close()
		return nil, err
	}
	if hello.ManifestDigest != client.ManifestDigest || !containsProtocol(hello.SupportedProtocols, guestproto.Version) {
		_ = secure.Close()
		return nil, fmt.Errorf("guest manifest or protocol identity mismatch")
	}
	acknowledgement, err := guestproto.NewFrame(guestproto.KindHelloAck, client.MachineID, "", 0, guestproto.HelloAck{
		AcceptedProtocol: guestproto.Version, ControllerVersion: client.ControllerVersion,
	})
	if err != nil {
		_ = secure.Close()
		return nil, err
	}
	if err := framing.Write(secure, acknowledgement, guestproto.MaxFrame); err != nil {
		_ = secure.Close()
		return nil, fmt.Errorf("write guest hello acknowledgement: %w", err)
	}
	if err := secure.SetDeadline(time.Time{}); err != nil {
		_ = secure.Close()
		return nil, fmt.Errorf("clear controller handshake deadline: %w", err)
	}
	return &Session{connection: secure, machineID: client.MachineID, bootID: hello.GuestBootID}, nil
}

func (session *Session) Close() error {
	if session == nil || session.connection == nil {
		return nil
	}
	return session.connection.Close()
}

func (session *Session) BootID() string { return session.bootID }

// Ping proves the authenticated guest session is live and bound to the same
// boot identity observed during hello.
func (session *Session) Ping(nonce string) error {
	request, err := guestproto.NewFrame(guestproto.KindPing, session.machineID, "", 0, guestproto.Ping{Nonce: nonce})
	if err != nil {
		return err
	}
	if err := session.write(request); err != nil {
		return err
	}
	var response guestproto.Frame
	if err := framing.Read(session.connection, &response, guestproto.MaxFrame); err != nil {
		return err
	}
	if err := guestproto.ValidateFrame(response); err != nil {
		return err
	}
	if response.Kind != guestproto.KindPong || response.MachineID != session.machineID {
		return fmt.Errorf("unexpected guest ping response")
	}
	var pong guestproto.Pong
	if err := guestproto.DecodePayload(response, &pong); err != nil {
		return err
	}
	if pong.Nonce != nonce || pong.GuestBootID != session.bootID {
		return fmt.Errorf("guest ping identity mismatch")
	}
	return nil
}

// Start begins or reattaches to one operation. Reusing the same operation ID
// and exact request causes the guest to replay stored frames instead of
// starting duplicate work.
func (session *Session) Start(operationID string, request guestproto.ExecStart) (*Execution, error) {
	session.activeMu.Lock()
	if session.active {
		session.activeMu.Unlock()
		return nil, fmt.Errorf("guest session already has an active foreground execution")
	}
	session.active = true
	session.activeMu.Unlock()
	frame, err := guestproto.NewFrame(guestproto.KindExecStart, session.machineID, operationID, 0, request)
	if err != nil {
		session.release()
		return nil, err
	}
	if err := session.write(frame); err != nil {
		session.release()
		return nil, err
	}
	return &Execution{session: session, operationID: operationID, nextInput: 1, nextOutput: 1}, nil
}

func (session *Session) write(frame guestproto.Frame) error {
	session.writeMu.Lock()
	defer session.writeMu.Unlock()
	return framing.Write(session.connection, frame, guestproto.MaxFrame)
}

func (session *Session) release() {
	session.activeMu.Lock()
	session.active = false
	session.activeMu.Unlock()
}

// Execution provides foreground stream/control access to one guest operation.
type Execution struct {
	session     *Session
	operationID string
	inputMu     sync.Mutex
	nextInput   uint64
	nextOutput  uint64
	terminal    bool
}

// Read returns the next validated stream or terminal frame.
func (execution *Execution) Read() (guestproto.Frame, error) {
	if execution.terminal {
		return guestproto.Frame{}, io.EOF
	}
	var frame guestproto.Frame
	if err := framing.Read(execution.session.connection, &frame, guestproto.MaxFrame); err != nil {
		return guestproto.Frame{}, err
	}
	if err := guestproto.ValidateFrame(frame); err != nil {
		return guestproto.Frame{}, err
	}
	if frame.MachineID != execution.session.machineID || frame.OperationID != execution.operationID {
		return guestproto.Frame{}, fmt.Errorf("guest execution frame identity mismatch")
	}
	if frame.Sequence != execution.nextOutput {
		return guestproto.Frame{}, fmt.Errorf("guest output sequence %d, expected %d", frame.Sequence, execution.nextOutput)
	}
	execution.nextOutput++
	if frame.Kind == guestproto.KindExit || frame.Kind == guestproto.KindError {
		execution.terminal = true
		execution.session.release()
	}
	return frame, nil
}

func (execution *Execution) Stdin(data []byte) error {
	if len(data) == 0 {
		return fmt.Errorf("stdin data is empty")
	}
	return execution.control(guestproto.KindStdin, guestproto.Data{Data: append([]byte(nil), data...)})
}

func (execution *Execution) StdinEOF() error {
	return execution.control(guestproto.KindStdinEOF, guestproto.Empty{})
}

func (execution *Execution) Resize(rows, cols uint16) error {
	return execution.control(guestproto.KindResize, guestproto.Resize{Rows: rows, Cols: cols})
}

func (execution *Execution) Signal(name string) error {
	return execution.control(guestproto.KindSignal, guestproto.Signal{Name: name})
}

func (execution *Execution) Cancel(reason string) error {
	return execution.control(guestproto.KindCancel, guestproto.Cancel{Reason: reason})
}

func (execution *Execution) control(kind string, payload any) error {
	execution.inputMu.Lock()
	defer execution.inputMu.Unlock()
	if execution.terminal {
		return fmt.Errorf("guest execution is terminal")
	}
	frame, err := guestproto.NewFrame(kind, execution.session.machineID, execution.operationID, execution.nextInput, payload)
	if err != nil {
		return err
	}
	if err := execution.session.write(frame); err != nil {
		return err
	}
	execution.nextInput++
	return nil
}

func containsProtocol(values []int, expected int) bool {
	for _, value := range values {
		if value == expected {
			return true
		}
	}
	return false
}
