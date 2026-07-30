package guestagent

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"regexp"
	"sync"
	"time"

	"github.com/StealthEyeLLC/ehjint/internal/framing"
	"github.com/StealthEyeLLC/ehjint/internal/guestproto"
	"github.com/StealthEyeLLC/ehjint/internal/pki"
	"github.com/StealthEyeLLC/ehjint/internal/vsock"
)

var bootIDPattern = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

const (
	handshakeTimeout = 15 * time.Second
	writeTimeout     = 15 * time.Second
	defaultMaxOutput = 16 * 1024 * 1024
	subscriberDepth  = 512
)

// Server is one machine-bound guest execution authority.
type Server struct {
	config     RuntimeConfig
	tlsConfig  *tls.Config
	bootID     string
	maxOutput  int64
	mu         sync.Mutex
	operations map[string]*operation
}

// NewServer creates a server using already verified identity material.
func NewServer(config RuntimeConfig, bootID string) (*Server, error) {
	if err := validateBootID(bootID); err != nil {
		return nil, err
	}
	tlsConfig, err := pki.ServerTLSConfig(config.Document.MachineID, config.Authority, config.Credentials, time.Now)
	if err != nil {
		return nil, fmt.Errorf("create guest TLS profile: %w", err)
	}
	return &Server{
		config: config, tlsConfig: tlsConfig, bootID: bootID,
		maxOutput: defaultMaxOutput, operations: make(map[string]*operation),
	}, nil
}

// Run loads the installed guest identity and serves native AF_VSOCK until the
// context is cancelled or the listener fails.
func Run(ctx context.Context, configPath string) error {
	config, err := LoadConfig(configPath, time.Now())
	if err != nil {
		return err
	}
	bootIDBytes, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil {
		return fmt.Errorf("read guest boot ID: %w", err)
	}
	server, err := NewServer(config, string(trimSpace(bootIDBytes)))
	if err != nil {
		return err
	}
	listener, err := vsock.Listen(config.Document.VsockPort)
	if err != nil {
		return err
	}
	defer listener.Close()
	go func() {
		<-ctx.Done()
		_ = listener.Close()
	}()
	for {
		connection, acceptErr := listener.Accept()
		if acceptErr != nil {
			if ctx.Err() != nil || acceptErr == net.ErrClosed {
				return ctx.Err()
			}
			return acceptErr
		}
		go func() {
			_ = server.ServeConn(connection)
		}()
	}
}

// ServeConn authenticates one controller and serves strict guest frames. It is
// exported for deterministic in-memory integration tests.
func (server *Server) ServeConn(raw net.Conn) error {
	if raw == nil {
		return fmt.Errorf("guest connection is required")
	}
	defer raw.Close()
	if err := raw.SetDeadline(time.Now().Add(handshakeTimeout)); err != nil {
		return fmt.Errorf("set guest handshake deadline: %w", err)
	}
	secure := tls.Server(raw, server.tlsConfig.Clone())
	if err := secure.Handshake(); err != nil {
		return fmt.Errorf("authenticate guest controller: %w", err)
	}
	hello, err := guestproto.NewFrame(guestproto.KindHello, server.config.Document.MachineID, "", 0, guestproto.Hello{
		AgentVersion: server.config.Document.AgentVersion, GuestBootID: server.bootID,
		ManifestDigest: server.config.Document.ManifestDigest, SupportedProtocols: []int{guestproto.Version},
	})
	if err != nil {
		return err
	}
	if err := framing.Write(secure, hello, guestproto.MaxFrame); err != nil {
		return fmt.Errorf("write guest hello: %w", err)
	}
	var acknowledgement guestproto.Frame
	if err := framing.Read(secure, &acknowledgement, guestproto.MaxFrame); err != nil {
		return fmt.Errorf("read guest hello acknowledgement: %w", err)
	}
	if err := guestproto.ValidateFrame(acknowledgement); err != nil {
		return fmt.Errorf("validate guest hello acknowledgement: %w", err)
	}
	if acknowledgement.Kind != guestproto.KindHelloAck || acknowledgement.MachineID != server.config.Document.MachineID {
		return fmt.Errorf("controller acknowledgement identity mismatch")
	}
	var accepted guestproto.HelloAck
	if err := guestproto.DecodePayload(acknowledgement, &accepted); err != nil {
		return err
	}
	if accepted.AcceptedProtocol != guestproto.Version {
		return fmt.Errorf("controller rejected guest protocol")
	}
	if err := secure.SetDeadline(time.Time{}); err != nil {
		return fmt.Errorf("clear guest handshake deadline: %w", err)
	}

	session := newSession(secure)
	defer session.close()
	go session.writeLoop()
	for {
		var frame guestproto.Frame
		if err := framing.Read(secure, &frame, guestproto.MaxFrame); err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed) || session.closed() {
				return nil
			}
			return fmt.Errorf("read guest request: %w", err)
		}
		if err := guestproto.ValidateFrame(frame); err != nil {
			return fmt.Errorf("validate guest request: %w", err)
		}
		if frame.MachineID != server.config.Document.MachineID {
			return fmt.Errorf("guest request machine identity mismatch")
		}
		if err := server.handle(session, frame); err != nil {
			return err
		}
	}
}

func (server *Server) handle(session *session, frame guestproto.Frame) error {
	switch frame.Kind {
	case guestproto.KindPing:
		var request guestproto.Ping
		if err := guestproto.DecodePayload(frame, &request); err != nil {
			return err
		}
		response, err := guestproto.NewFrame(guestproto.KindPong, frame.MachineID, "", 0, guestproto.Pong{Nonce: request.Nonce, GuestBootID: server.bootID})
		if err != nil {
			return err
		}
		return session.enqueue(response)
	case guestproto.KindExecStart:
		return server.startOrAttach(session, frame)
	case guestproto.KindStdin, guestproto.KindStdinEOF, guestproto.KindResize, guestproto.KindSignal, guestproto.KindCancel:
		operation := server.lookup(frame.OperationID)
		if operation == nil {
			return session.enqueue(protocolErrorFrame(frame.MachineID, frame.OperationID, 1, "not_found", "guest operation was not found", false))
		}
		return operation.handleInput(frame)
	case guestproto.KindFilePutStart, guestproto.KindFileChunk, guestproto.KindFilePutEnd, guestproto.KindFileGet:
		return session.enqueue(protocolErrorFrame(frame.MachineID, frame.OperationID, 1, "unavailable", "general file operations are not enabled in Mission 2", false))
	default:
		return fmt.Errorf("controller sent response-only guest frame %q", frame.Kind)
	}
}

func (server *Server) startOrAttach(session *session, frame guestproto.Frame) error {
	var request guestproto.ExecStart
	if err := guestproto.DecodePayload(frame, &request); err != nil {
		return err
	}
	digest, err := requestDigest(frame.Payload)
	if err != nil {
		return err
	}
	server.mu.Lock()
	existing := server.operations[frame.OperationID]
	if existing != nil {
		server.mu.Unlock()
		if existing.digest != digest {
			return session.enqueue(protocolErrorFrame(frame.MachineID, frame.OperationID, 1, "conflict", "operation ID was reused with different execution input", false))
		}
		return existing.subscribe(session)
	}
	operation := newOperation(server, frame.OperationID, digest, request)
	server.operations[frame.OperationID] = operation
	server.mu.Unlock()
	if err := operation.subscribe(session); err != nil {
		return err
	}
	go operation.run()
	return nil
}

func (server *Server) lookup(operationID string) *operation {
	server.mu.Lock()
	defer server.mu.Unlock()
	return server.operations[operationID]
}

type session struct {
	connection net.Conn
	outgoing   chan guestproto.Frame
	done       chan struct{}
	closeOne   sync.Once
}

func newSession(connection net.Conn) *session {
	return &session{connection: connection, outgoing: make(chan guestproto.Frame, subscriberDepth), done: make(chan struct{})}
}

func (session *session) enqueue(frame guestproto.Frame) error {
	select {
	case <-session.done:
		return net.ErrClosed
	case session.outgoing <- frame:
		return nil
	default:
		session.close()
		return fmt.Errorf("guest subscriber exceeded bounded output queue")
	}
}

func (session *session) writeLoop() {
	for {
		select {
		case <-session.done:
			return
		case frame := <-session.outgoing:
			if err := session.connection.SetWriteDeadline(time.Now().Add(writeTimeout)); err != nil {
				session.close()
				return
			}
			if err := framing.Write(session.connection, frame, guestproto.MaxFrame); err != nil {
				session.close()
				return
			}
			_ = session.connection.SetWriteDeadline(time.Time{})
		}
	}
}

func (session *session) close() {
	session.closeOne.Do(func() {
		close(session.done)
		_ = session.connection.Close()
	})
}

func (session *session) closed() bool {
	select {
	case <-session.done:
		return true
	default:
		return false
	}
}

func protocolErrorFrame(machineID, operationID string, sequence uint64, code, message string, retryable bool) guestproto.Frame {
	frame, err := guestproto.NewFrame(guestproto.KindError, machineID, operationID, sequence, guestproto.ProtocolError{Code: code, Message: message, Retryable: retryable})
	if err != nil {
		panic(err)
	}
	return frame
}

func validateBootID(value string) error {
	if !bootIDPattern.MatchString(value) {
		return fmt.Errorf("invalid guest boot ID")
	}
	return nil
}

func trimSpace(data []byte) []byte {
	start, end := 0, len(data)
	for start < end && (data[start] == ' ' || data[start] == '\n' || data[start] == '\r' || data[start] == '\t') {
		start++
	}
	for end > start && (data[end-1] == ' ' || data[end-1] == '\n' || data[end-1] == '\r' || data[end-1] == '\t') {
		end--
	}
	return data[start:end]
}
