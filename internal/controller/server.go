package controller

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/StealthEyeLLC/ehjint/internal/contracts"
	"github.com/StealthEyeLLC/ehjint/internal/controlproto"
	"github.com/StealthEyeLLC/ehjint/internal/framing"
	"github.com/StealthEyeLLC/ehjint/internal/layout"
	"golang.org/x/sys/unix"
)

// OperationValidator rejects unknown names or versions before authorization.
type OperationValidator func(operation string, version int) error

// ServerConfig contains explicit local controller authority.
type ServerConfig struct {
	Paths             layout.Paths
	SocketUID         int
	SocketGID         int
	Policy            Policy
	Handler           Handler
	ValidateOperation OperationValidator
	RequestTimeout    time.Duration
	MaxConnections    int
}

// Server owns one singleton lock and Unix listener.
type Server struct {
	config   ServerConfig
	lockFile *os.File
	listener *net.UnixListener
	mu       sync.Mutex
}

// NewServer validates configuration without mutating host state.
func NewServer(config ServerConfig) (*Server, error) {
	if config.Handler == nil || config.ValidateOperation == nil {
		return nil, fmt.Errorf("controller handler and operation validator are required")
	}
	if config.Paths.Root == "" || config.Paths.Run == "" || config.Paths.ControllerSocket == "" || config.Paths.ControllerLock == "" {
		return nil, fmt.Errorf("complete controller paths are required")
	}
	if config.SocketUID < 0 || config.SocketGID < 0 || config.Policy.GroupID < 0 {
		return nil, fmt.Errorf("controller UID/GID policy must be explicit")
	}
	if config.RequestTimeout <= 0 {
		config.RequestTimeout = DefaultRequestTimeout
	}
	if config.MaxConnections <= 0 {
		config.MaxConnections = DefaultMaxConnections
	}
	return &Server{config: config}, nil
}

// ListenAndServe acquires singleton authority, creates the authenticated socket,
// and serves until context cancellation or listener failure.
func (server *Server) ListenAndServe(ctx context.Context) error {
	if ctx == nil {
		return fmt.Errorf("controller context is required")
	}
	if err := server.acquire(); err != nil {
		return err
	}
	defer server.release()

	listener := server.listener
	closeDone := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			_ = listener.Close()
		case <-closeDone:
		}
	}()
	defer close(closeDone)

	semaphore := make(chan struct{}, server.config.MaxConnections)
	var workers sync.WaitGroup
	defer workers.Wait()
	for {
		connection, err := listener.AcceptUnix()
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return nil
			}
			return fmt.Errorf("accept controller connection: %w", err)
		}
		select {
		case semaphore <- struct{}{}:
			workers.Add(1)
			go func() {
				defer workers.Done()
				defer func() { <-semaphore }()
				server.handleConnection(ctx, connection)
			}()
		default:
			_ = connection.Close()
		}
	}
}

// Close interrupts a serving listener. It is idempotent.
func (server *Server) Close() error {
	server.mu.Lock()
	defer server.mu.Unlock()
	if server.listener == nil {
		return nil
	}
	return server.listener.Close()
}

func (server *Server) acquire() error {
	server.mu.Lock()
	defer server.mu.Unlock()
	if server.listener != nil || server.lockFile != nil {
		return fmt.Errorf("controller server is already acquired")
	}
	if err := secureDirectory(server.config.Paths.Root, server.config.Paths.Run, 0o750, server.config.SocketUID, server.config.SocketGID); err != nil {
		return err
	}
	lock, err := os.OpenFile(server.config.Paths.ControllerLock, os.O_RDWR|os.O_CREATE, 0o640)
	if err != nil {
		return fmt.Errorf("open controller singleton lock: %w", err)
	}
	if err := lock.Chmod(0o640); err != nil {
		_ = lock.Close()
		return fmt.Errorf("set controller lock mode: %w", err)
	}
	if err := lock.Chown(server.config.SocketUID, server.config.SocketGID); err != nil {
		_ = lock.Close()
		return fmt.Errorf("set controller lock owner: %w", err)
	}
	if err := unix.Flock(int(lock.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		_ = lock.Close()
		return fmt.Errorf("controller singleton lock is held: %w", err)
	}
	cleanupLock := func() {
		_ = unix.Flock(int(lock.Fd()), unix.LOCK_UN)
		_ = lock.Close()
	}
	if err := removeStaleSocket(server.config.Paths.ControllerSocket); err != nil {
		cleanupLock()
		return err
	}
	address := &net.UnixAddr{Name: server.config.Paths.ControllerSocket, Net: "unix"}
	listener, err := net.ListenUnix("unix", address)
	if err != nil {
		cleanupLock()
		return fmt.Errorf("listen on controller socket: %w", err)
	}
	if err := os.Chmod(server.config.Paths.ControllerSocket, 0o660); err != nil {
		_ = listener.Close()
		cleanupLock()
		return fmt.Errorf("set controller socket mode: %w", err)
	}
	if err := os.Chown(server.config.Paths.ControllerSocket, server.config.SocketUID, server.config.SocketGID); err != nil {
		_ = listener.Close()
		cleanupLock()
		return fmt.Errorf("set controller socket owner: %w", err)
	}
	server.lockFile = lock
	server.listener = listener
	return nil
}

func (server *Server) release() {
	server.mu.Lock()
	defer server.mu.Unlock()
	if server.listener != nil {
		_ = server.listener.Close()
		server.listener = nil
	}
	_ = os.Remove(server.config.Paths.ControllerSocket)
	if server.lockFile != nil {
		_ = unix.Flock(int(server.lockFile.Fd()), unix.LOCK_UN)
		_ = server.lockFile.Close()
		server.lockFile = nil
	}
}

func (server *Server) handleConnection(parent context.Context, connection *net.UnixConn) {
	defer connection.Close()
	now := time.Now()
	_ = connection.SetDeadline(now.Add(server.config.RequestTimeout))
	peer, err := inspectPeer(connection)
	if err != nil {
		return
	}
	var request controlproto.Request
	if err := framing.Read(connection, &request, controlproto.MaxFrame); err != nil {
		return
	}
	responder := newResponder(request.RequestID, connectionFrameWriter{writer: connection})
	if err := controlproto.ValidateRequest(request); err != nil {
		_ = responder.Error(publicError(request.Operation, contracts.CodeInvalidArgument, "invalid controller request", false, "").Envelope)
		return
	}
	if err := server.config.ValidateOperation(request.Operation, request.OperationVersion); err != nil {
		_ = responder.Error(publicError(request.Operation, contracts.CodeNotFound, "operation or version is not registered", false, "").Envelope)
		return
	}
	if err := server.config.Policy.Authorize(peer, request.Operation); err != nil {
		_ = responder.Error(publicError(request.Operation, contracts.CodePermissionDenied, "peer is not authorized for this operation", false, "").Envelope)
		return
	}
	deadline := deadlineFromRequest(now, request)
	if maximum := now.Add(server.config.RequestTimeout); deadline.After(maximum) {
		deadline = maximum
	}
	_ = connection.SetDeadline(deadline)
	ctx, cancel := context.WithDeadline(parent, deadline)
	defer cancel()
	if err := server.config.Handler.Handle(ctx, request, peer, responder); err != nil && !responder.isTerminal() {
		var safe *PublicError
		if errors.As(err, &safe) {
			_ = responder.Error(safe.Envelope)
		} else {
			_ = responder.Error(publicError(request.Operation, contracts.CodeInternal, "controller operation failed", true, "").Envelope)
		}
	}
	if !responder.isTerminal() {
		_ = responder.Error(publicError(request.Operation, contracts.CodeInternal, "controller handler returned without terminal response", false, "").Envelope)
	}
}

func secureDirectory(root, destination string, mode os.FileMode, uid, gid int) error {
	cleanRoot := filepath.Clean(root)
	cleanDestination := filepath.Clean(destination)
	if !filepath.IsAbs(cleanRoot) || !filepath.IsAbs(cleanDestination) || (cleanDestination != cleanRoot && !layout.Within(cleanRoot, cleanDestination)) {
		return fmt.Errorf("controller directory escapes managed root")
	}
	rootInfo, err := os.Lstat(cleanRoot)
	if err != nil {
		return fmt.Errorf("inspect controller managed root: %w", err)
	}
	if rootInfo.Mode()&os.ModeSymlink != 0 || !rootInfo.IsDir() || rootInfo.Mode().Perm()&0o002 != 0 {
		return fmt.Errorf("controller managed root is not a safe real directory")
	}
	relative, err := filepath.Rel(cleanRoot, cleanDestination)
	if err != nil {
		return fmt.Errorf("resolve controller directory: %w", err)
	}
	current := cleanRoot
	components := []string{}
	if relative != "." {
		for cursor := relative; cursor != "." && cursor != ""; {
			directory, file := filepath.Split(cursor)
			if file != "" {
				components = append([]string{file}, components...)
			}
			cursor = filepath.Clean(directory)
		}
	}
	for _, component := range components {
		current = filepath.Join(current, component)
		info, statErr := os.Lstat(current)
		if errors.Is(statErr, os.ErrNotExist) {
			if err := os.Mkdir(current, 0o750); err != nil {
				return fmt.Errorf("create controller directory %s: %w", current, err)
			}
			continue
		}
		if statErr != nil {
			return fmt.Errorf("inspect controller directory %s: %w", current, statErr)
		}
		if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
			return fmt.Errorf("controller path component is not a real directory: %s", current)
		}
		if info.Mode().Perm()&0o002 != 0 {
			return fmt.Errorf("controller path component is world-writable: %s", current)
		}
	}
	if err := os.Chmod(cleanDestination, mode); err != nil {
		return fmt.Errorf("set controller directory mode: %w", err)
	}
	if err := os.Chown(cleanDestination, uid, gid); err != nil {
		return fmt.Errorf("set controller directory owner: %w", err)
	}
	return nil
}

func removeStaleSocket(path string) error {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("inspect controller socket: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || info.Mode()&os.ModeSocket == 0 {
		return fmt.Errorf("controller socket path is not a socket")
	}
	if err := os.Remove(path); err != nil {
		return fmt.Errorf("remove stale controller socket: %w", err)
	}
	return nil
}
