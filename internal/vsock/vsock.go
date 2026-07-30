// Package vsock provides the narrow Linux AF_VSOCK listener required by the
// EHJINT guest agent without adding a second transport dependency.
package vsock

import (
	"fmt"
	"io"
	"net"
	"os"
	"sync"
	"time"

	"golang.org/x/sys/unix"
)

// Addr is one AF_VSOCK endpoint.
type Addr struct {
	CID  uint32
	Port uint32
}

func (address Addr) Network() string { return "vsock" }
func (address Addr) String() string  { return fmt.Sprintf("vsock:%d:%d", address.CID, address.Port) }

// Listener owns one blocking AF_VSOCK stream listener.
type Listener struct {
	fd       int
	address  Addr
	closeOne sync.Once
}

// Listen creates a guest listener on any local CID and the exact nonzero port.
func Listen(port uint32) (*Listener, error) {
	if port == 0 {
		return nil, fmt.Errorf("vsock port must be nonzero")
	}
	fd, err := unix.Socket(unix.AF_VSOCK, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("create AF_VSOCK listener: %w", err)
	}
	listener := &Listener{fd: fd, address: Addr{CID: unix.VMADDR_CID_ANY, Port: port}}
	cleanup := true
	defer func() {
		if cleanup {
			_ = listener.Close()
		}
	}()
	if err := unix.Bind(fd, &unix.SockaddrVM{CID: unix.VMADDR_CID_ANY, Port: port}); err != nil {
		return nil, fmt.Errorf("bind AF_VSOCK port %d: %w", port, err)
	}
	if err := unix.Listen(fd, 64); err != nil {
		return nil, fmt.Errorf("listen on AF_VSOCK port %d: %w", port, err)
	}
	cleanup = false
	return listener, nil
}

func (listener *Listener) Accept() (net.Conn, error) {
	if listener == nil || listener.fd < 0 {
		return nil, net.ErrClosed
	}
	fd, remote, err := unix.Accept4(listener.fd, unix.SOCK_CLOEXEC)
	if err != nil {
		if err == unix.EBADF || err == unix.EINVAL {
			return nil, net.ErrClosed
		}
		return nil, fmt.Errorf("accept AF_VSOCK connection: %w", err)
	}
	remoteVM, ok := remote.(*unix.SockaddrVM)
	if !ok {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("accepted non-vsock peer")
	}
	local, err := unix.Getsockname(fd)
	if err != nil {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("inspect local AF_VSOCK endpoint: %w", err)
	}
	localVM, ok := local.(*unix.SockaddrVM)
	if !ok {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("accepted socket has non-vsock local endpoint")
	}
	return &Conn{fd: fd, local: Addr{CID: localVM.CID, Port: localVM.Port}, remote: Addr{CID: remoteVM.CID, Port: remoteVM.Port}}, nil
}

func (listener *Listener) Close() error {
	if listener == nil {
		return nil
	}
	var result error
	listener.closeOne.Do(func() {
		if listener.fd >= 0 {
			result = unix.Close(listener.fd)
			listener.fd = -1
		}
	})
	return result
}

func (listener *Listener) Addr() net.Addr {
	if listener == nil {
		return Addr{}
	}
	return listener.address
}

// Conn is one blocking AF_VSOCK stream with socket-level deadlines.
type Conn struct {
	fd       int
	local    Addr
	remote   Addr
	closeOne sync.Once
	readMu   sync.Mutex
	writeMu  sync.Mutex
}

func (connection *Conn) Read(destination []byte) (int, error) {
	connection.readMu.Lock()
	defer connection.readMu.Unlock()
	for {
		count, err := unix.Read(connection.fd, destination)
		if err == unix.EINTR {
			continue
		}
		if err == unix.EAGAIN || err == unix.EWOULDBLOCK {
			return 0, os.ErrDeadlineExceeded
		}
		if err != nil {
			return count, os.NewSyscallError("read", err)
		}
		if count == 0 {
			return 0, io.EOF
		}
		return count, nil
	}
}

func (connection *Conn) Write(data []byte) (int, error) {
	connection.writeMu.Lock()
	defer connection.writeMu.Unlock()
	written := 0
	for written < len(data) {
		count, err := unix.Write(connection.fd, data[written:])
		if err == unix.EINTR {
			continue
		}
		if err == unix.EAGAIN || err == unix.EWOULDBLOCK {
			return written, os.ErrDeadlineExceeded
		}
		if err != nil {
			return written, os.NewSyscallError("write", err)
		}
		if count <= 0 {
			return written, fmt.Errorf("AF_VSOCK write made no progress")
		}
		written += count
	}
	return written, nil
}

func (connection *Conn) Close() error {
	if connection == nil {
		return nil
	}
	var result error
	connection.closeOne.Do(func() {
		if connection.fd >= 0 {
			result = unix.Close(connection.fd)
			connection.fd = -1
		}
	})
	return result
}

func (connection *Conn) LocalAddr() net.Addr  { return connection.local }
func (connection *Conn) RemoteAddr() net.Addr { return connection.remote }

func (connection *Conn) SetDeadline(deadline time.Time) error {
	if err := connection.SetReadDeadline(deadline); err != nil {
		return err
	}
	return connection.SetWriteDeadline(deadline)
}

func (connection *Conn) SetReadDeadline(deadline time.Time) error {
	return setTimeout(connection.fd, unix.SO_RCVTIMEO, deadline)
}

func (connection *Conn) SetWriteDeadline(deadline time.Time) error {
	return setTimeout(connection.fd, unix.SO_SNDTIMEO, deadline)
}

func setTimeout(fd, option int, deadline time.Time) error {
	var timeout unix.Timeval
	if !deadline.IsZero() {
		duration := time.Until(deadline)
		if duration <= 0 {
			duration = time.Microsecond
		}
		timeout = unix.NsecToTimeval(duration.Nanoseconds())
	}
	if err := unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, option, &timeout); err != nil {
		return os.NewSyscallError("setsockopt", err)
	}
	return nil
}
