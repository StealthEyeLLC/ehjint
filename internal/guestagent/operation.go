package guestagent

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/StealthEyeLLC/ehjint/internal/contracts"
	"github.com/StealthEyeLLC/ehjint/internal/guestproto"
)

const cancelGrace = 2 * time.Second

var defaultEnvironment = map[string]string{
	"HOME":    "/root",
	"LOGNAME": "root",
	"PATH":    "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
	"SHELL":   "/bin/sh",
	"USER":    "root",
}

type operation struct {
	server  *Server
	id      string
	digest  string
	request guestproto.ExecStart

	mu          sync.Mutex
	ptyMu       sync.Mutex
	frames      []guestproto.Frame
	subscribers map[*session]struct{}
	nextOutput  uint64
	nextInput   uint64
	outputBytes int64
	terminal    bool
	cmd         *exec.Cmd
	stdin       io.WriteCloser
	pty         *os.File
	reason      string
	ready       chan struct{}
	done        chan struct{}
	readyOnce   sync.Once
	doneOnce    sync.Once
}

func newOperation(server *Server, id, digest string, request guestproto.ExecStart) *operation {
	return &operation{
		server: server, id: id, digest: digest, request: request,
		subscribers: make(map[*session]struct{}), nextOutput: 1, nextInput: 1,
		ready: make(chan struct{}), done: make(chan struct{}),
	}
}

func (operation *operation) subscribe(subscriber *session) error {
	operation.mu.Lock()
	frames := append([]guestproto.Frame(nil), operation.frames...)
	if !operation.terminal {
		operation.subscribers[subscriber] = struct{}{}
	}
	operation.mu.Unlock()
	for _, frame := range frames {
		if err := subscriber.enqueue(frame); err != nil {
			operation.removeSubscriber(subscriber)
			return err
		}
	}
	return nil
}

func (operation *operation) removeSubscriber(subscriber *session) {
	operation.mu.Lock()
	delete(operation.subscribers, subscriber)
	operation.mu.Unlock()
}

func (operation *operation) emit(kind string, payload any, dataBytes int, terminal bool) error {
	operation.mu.Lock()
	if operation.terminal {
		operation.mu.Unlock()
		return fmt.Errorf("guest operation is already terminal")
	}
	if dataBytes > 0 && operation.outputBytes+int64(dataBytes) > operation.server.maxOutput {
		operation.mu.Unlock()
		operation.terminate("output_limit")
		return fmt.Errorf("guest operation exceeded bounded output spool")
	}
	sequence := operation.nextOutput
	operation.nextOutput++
	frame, err := guestproto.NewFrame(kind, operation.server.config.Document.MachineID, operation.id, sequence, payload)
	if err != nil {
		operation.mu.Unlock()
		return err
	}
	operation.outputBytes += int64(dataBytes)
	operation.frames = append(operation.frames, frame)
	if terminal {
		operation.terminal = true
	}
	subscribers := make([]*session, 0, len(operation.subscribers))
	for subscriber := range operation.subscribers {
		subscribers = append(subscribers, subscriber)
	}
	if terminal {
		clear(operation.subscribers)
	}
	operation.mu.Unlock()
	for _, subscriber := range subscribers {
		if err := subscriber.enqueue(frame); err != nil {
			operation.removeSubscriber(subscriber)
		}
	}
	return nil
}

func (operation *operation) emitError(code, message string, retryable bool) {
	_ = operation.emit(guestproto.KindError, guestproto.ProtocolError{Code: code, Message: message, Retryable: retryable}, 0, true)
	operation.finish()
}

func (operation *operation) run() {
	if operation.request.User != "root" || operation.request.Group != "root" {
		operation.markReady()
		operation.emitError("permission_denied", "Mission 2 guest execution requires exact root:root identity", false)
		return
	}
	environmentInput := append([]string(nil), operation.request.Environment...)
	if operation.request.PTY != nil {
		environmentInput = append(environmentInput, "TERM="+operation.request.PTY.Term)
	}
	executable, environment, err := resolveCommand(operation.request.Argv[0], environmentInput)
	if err != nil {
		operation.markReady()
		operation.emitError("exec_failed", err.Error(), false)
		return
	}
	command := exec.Command(executable, operation.request.Argv[1:]...)
	command.Args = append([]string(nil), operation.request.Argv...)
	command.Env = environment
	command.Dir = operation.request.WorkingDirectory

	var streams sync.WaitGroup
	if operation.request.PTY != nil {
		master, slave, ptyErr := openPTY(operation.request.PTY.Rows, operation.request.PTY.Cols)
		if ptyErr != nil {
			operation.markReady()
			operation.emitError("exec_failed", "allocate guest PTY: "+ptyErr.Error(), false)
			return
		}
		operation.pty = master
		command.Stdin, command.Stdout, command.Stderr = slave, slave, slave
		command.SysProcAttr = rootProcessAttributes(true)
		if startErr := command.Start(); startErr != nil {
			_ = master.Close()
			_ = slave.Close()
			operation.markReady()
			operation.emitError("exec_failed", "start guest command: "+startErr.Error(), false)
			return
		}
		_ = slave.Close()
		operation.setCommand(command, nil, master)
		streams.Add(1)
		go func() {
			defer streams.Done()
			operation.copyOutput(guestproto.KindStdout, master, true)
		}()
	} else {
		var stdin io.WriteCloser
		if operation.request.Stdin {
			stdin, err = command.StdinPipe()
			if err != nil {
				operation.markReady()
				operation.emitError("exec_failed", "create guest stdin: "+err.Error(), false)
				return
			}
		}
		stdout, stdoutErr := command.StdoutPipe()
		if stdoutErr != nil {
			operation.markReady()
			operation.emitError("exec_failed", "create guest stdout: "+stdoutErr.Error(), false)
			return
		}
		stderr, stderrErr := command.StderrPipe()
		if stderrErr != nil {
			operation.markReady()
			operation.emitError("exec_failed", "create guest stderr: "+stderrErr.Error(), false)
			return
		}
		command.SysProcAttr = rootProcessAttributes(false)
		if startErr := command.Start(); startErr != nil {
			operation.markReady()
			operation.emitError("exec_failed", "start guest command: "+startErr.Error(), false)
			return
		}
		operation.setCommand(command, stdin, nil)
		streams.Add(2)
		go func() {
			defer streams.Done()
			operation.copyOutput(guestproto.KindStdout, stdout, false)
		}()
		go func() {
			defer streams.Done()
			operation.copyOutput(guestproto.KindStderr, stderr, false)
		}()
	}

	var timeout *time.Timer
	if operation.request.TimeoutMillis > 0 {
		timeout = time.AfterFunc(time.Duration(operation.request.TimeoutMillis)*time.Millisecond, func() {
			operation.terminate("timeout")
		})
	}
	streams.Wait()
	waitErr := command.Wait()
	if timeout != nil {
		timeout.Stop()
	}
	if operation.pty != nil {
		operation.ptyMu.Lock()
		_ = operation.pty.Close()
		operation.ptyMu.Unlock()
	}
	operation.complete(waitErr)
}

func (operation *operation) setCommand(command *exec.Cmd, stdin io.WriteCloser, pty *os.File) {
	operation.mu.Lock()
	operation.cmd, operation.stdin, operation.pty = command, stdin, pty
	operation.mu.Unlock()
	operation.markReady()
}

func (operation *operation) markReady() {
	operation.readyOnce.Do(func() { close(operation.ready) })
}

func (operation *operation) finish() {
	operation.doneOnce.Do(func() { close(operation.done) })
}

func (operation *operation) copyOutput(kind string, reader io.Reader, pty bool) {
	buffer := make([]byte, guestproto.MaxData)
	for {
		count, err := reader.Read(buffer)
		if count > 0 {
			data := append([]byte(nil), buffer[:count]...)
			if emitErr := operation.emit(kind, guestproto.Data{Data: data}, count, false); emitErr != nil {
				return
			}
		}
		if err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, os.ErrClosed) || errors.Is(err, syscall.EBADF) ||
				(pty && errors.Is(err, syscall.EIO)) || operation.isTerminating() {
				return
			}
			operation.terminate("io_failure")
			return
		}
	}
}

func (operation *operation) complete(waitErr error) {
	operation.mu.Lock()
	reason := operation.reason
	operation.mu.Unlock()
	switch reason {
	case "timeout":
		operation.emitError("timeout", "guest command exceeded its declared timeout", false)
		return
	case "cancelled":
		operation.emitError("cancelled", "guest command was cancelled", false)
		return
	case "output_limit":
		operation.emitError("io_failed", "guest command exceeded bounded output storage", false)
		return
	case "io_failure":
		operation.emitError("io_failed", "guest command output stream failed", false)
		return
	}
	status := 0
	signal := ""
	coreDumped := false
	if waitErr != nil {
		var exitError *exec.ExitError
		if !errors.As(waitErr, &exitError) {
			operation.emitError("exec_failed", "wait for guest command: "+waitErr.Error(), false)
			return
		}
		waitStatus, ok := exitError.Sys().(syscall.WaitStatus)
		if !ok {
			operation.emitError("exec_failed", "guest command returned unknown wait status", false)
			return
		}
		if waitStatus.Signaled() {
			signal = signalName(waitStatus.Signal())
			if signal == "" {
				operation.emitError("exec_failed", fmt.Sprintf("guest command died from unsupported signal %d", waitStatus.Signal()), false)
				return
			}
			status = 128 + int(waitStatus.Signal())
			if status > 255 {
				status = 255
			}
			coreDumped = waitStatus.CoreDump()
		} else {
			status = waitStatus.ExitStatus()
		}
	}
	_ = operation.emit(guestproto.KindExit, guestproto.Exit{Status: status, Signal: signal, CoreDumped: coreDumped}, 0, true)
	operation.finish()
}

func (operation *operation) handleInput(frame guestproto.Frame) error {
	select {
	case <-operation.ready:
	case <-operation.done:
		return fmt.Errorf("guest operation is already terminal")
	case <-time.After(handshakeTimeout):
		return fmt.Errorf("guest operation did not become ready")
	}
	operation.mu.Lock()
	if frame.Sequence != operation.nextInput {
		expected := operation.nextInput
		operation.mu.Unlock()
		return fmt.Errorf("guest input sequence %d, expected %d", frame.Sequence, expected)
	}
	operation.nextInput++
	command, stdin, master := operation.cmd, operation.stdin, operation.pty
	operation.mu.Unlock()
	if command == nil || command.Process == nil {
		return fmt.Errorf("guest command is not running")
	}
	switch frame.Kind {
	case guestproto.KindStdin:
		var payload guestproto.Data
		if err := guestproto.DecodePayload(frame, &payload); err != nil {
			return err
		}
		writer := io.Writer(stdin)
		if master != nil {
			operation.ptyMu.Lock()
			defer operation.ptyMu.Unlock()
			writer = master
		}
		if writer == nil {
			return fmt.Errorf("guest command did not declare stdin")
		}
		_, err := writer.Write(payload.Data)
		return err
	case guestproto.KindStdinEOF:
		if master != nil {
			operation.ptyMu.Lock()
			defer operation.ptyMu.Unlock()
			_, err := master.Write([]byte{4})
			return err
		}
		if stdin == nil {
			return fmt.Errorf("guest command did not declare stdin")
		}
		return stdin.Close()
	case guestproto.KindResize:
		if master == nil {
			return fmt.Errorf("guest command has no PTY")
		}
		var payload guestproto.Resize
		if err := guestproto.DecodePayload(frame, &payload); err != nil {
			return err
		}
		operation.ptyMu.Lock()
		defer operation.ptyMu.Unlock()
		return resizePTY(master, payload.Rows, payload.Cols)
	case guestproto.KindSignal:
		var payload guestproto.Signal
		if err := guestproto.DecodePayload(frame, &payload); err != nil {
			return err
		}
		signal, ok := parseSignal(payload.Name)
		if !ok {
			return fmt.Errorf("unsupported guest signal %q", payload.Name)
		}
		return syscall.Kill(-command.Process.Pid, signal)
	case guestproto.KindCancel:
		operation.terminate("cancelled")
		return nil
	default:
		return fmt.Errorf("unsupported guest input frame %q", frame.Kind)
	}
}

func (operation *operation) terminate(reason string) {
	operation.mu.Lock()
	if operation.terminal || operation.reason != "" {
		operation.mu.Unlock()
		return
	}
	operation.reason = reason
	command := operation.cmd
	operation.mu.Unlock()
	if command == nil || command.Process == nil {
		return
	}
	_ = syscall.Kill(-command.Process.Pid, syscall.SIGTERM)
	go func(pid int) {
		timer := time.NewTimer(cancelGrace)
		defer timer.Stop()
		select {
		case <-operation.done:
			return
		case <-timer.C:
			_ = syscall.Kill(-pid, syscall.SIGKILL)
		}
	}(command.Process.Pid)
}

func (operation *operation) isTerminating() bool {
	operation.mu.Lock()
	defer operation.mu.Unlock()
	return operation.reason != ""
}

func requestDigest(payload json.RawMessage) (string, error) {
	canonical, err := contracts.CanonicalJSON(payload)
	if err != nil {
		return "", fmt.Errorf("canonicalize guest execution request: %w", err)
	}
	sum := sha256.Sum256(canonical)
	return hex.EncodeToString(sum[:]), nil
}

func resolveCommand(name string, supplied []string) (string, []string, error) {
	environment := make(map[string]string, len(defaultEnvironment)+len(supplied))
	for key, value := range defaultEnvironment {
		environment[key] = value
	}
	for _, entry := range supplied {
		key, value, ok := strings.Cut(entry, "=")
		if !ok {
			return "", nil, fmt.Errorf("invalid environment entry")
		}
		environment[key] = value
	}
	var executable string
	if strings.ContainsRune(name, filepath.Separator) {
		if !filepath.IsAbs(name) || filepath.Clean(name) != name {
			return "", nil, fmt.Errorf("command path must be canonical absolute path")
		}
		executable = name
	} else {
		for _, directory := range filepath.SplitList(environment["PATH"]) {
			if !filepath.IsAbs(directory) || filepath.Clean(directory) != directory {
				return "", nil, fmt.Errorf("PATH contains a non-canonical directory")
			}
			candidate := filepath.Join(directory, name)
			info, err := os.Stat(candidate)
			if err == nil && info.Mode().IsRegular() && info.Mode().Perm()&0o111 != 0 {
				executable = candidate
				break
			}
		}
		if executable == "" {
			return "", nil, fmt.Errorf("command %q was not found in the declared PATH", name)
		}
	}
	info, err := os.Stat(executable)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o111 == 0 {
		return "", nil, fmt.Errorf("command executable is unavailable or not executable")
	}
	keys := make([]string, 0, len(environment))
	for key := range environment {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	encoded := make([]string, 0, len(keys))
	for _, key := range keys {
		encoded = append(encoded, key+"="+environment[key])
	}
	return executable, encoded, nil
}

func rootProcessAttributes(pty bool) *syscall.SysProcAttr {
	attributes := &syscall.SysProcAttr{
		Credential: &syscall.Credential{Uid: 0, Gid: 0, Groups: []uint32{}},
		Pdeathsig:  syscall.SIGKILL,
	}
	if pty {
		attributes.Setsid = true
		attributes.Setctty = true
		attributes.Ctty = 0
	} else {
		attributes.Setpgid = true
	}
	return attributes
}

func parseSignal(name string) (syscall.Signal, bool) {
	for signal, candidate := range signalNames {
		if candidate == name {
			return signal, true
		}
	}
	return 0, false
}

func signalName(signal syscall.Signal) string { return signalNames[signal] }

var signalNames = map[syscall.Signal]string{
	syscall.SIGHUP: "SIGHUP", syscall.SIGINT: "SIGINT", syscall.SIGQUIT: "SIGQUIT",
	syscall.SIGILL: "SIGILL", syscall.SIGTRAP: "SIGTRAP", syscall.SIGABRT: "SIGABRT",
	syscall.SIGBUS: "SIGBUS", syscall.SIGFPE: "SIGFPE", syscall.SIGKILL: "SIGKILL",
	syscall.SIGUSR1: "SIGUSR1", syscall.SIGSEGV: "SIGSEGV", syscall.SIGUSR2: "SIGUSR2",
	syscall.SIGPIPE: "SIGPIPE", syscall.SIGALRM: "SIGALRM", syscall.SIGTERM: "SIGTERM",
	syscall.SIGCHLD: "SIGCHLD", syscall.SIGCONT: "SIGCONT", syscall.SIGSTOP: "SIGSTOP",
	syscall.SIGTSTP: "SIGTSTP", syscall.SIGTTIN: "SIGTTIN", syscall.SIGTTOU: "SIGTTOU",
	syscall.SIGURG: "SIGURG", syscall.SIGXCPU: "SIGXCPU", syscall.SIGXFSZ: "SIGXFSZ",
	syscall.SIGVTALRM: "SIGVTALRM", syscall.SIGPROF: "SIGPROF", syscall.SIGWINCH: "SIGWINCH",
	syscall.SIGIO: "SIGIO", syscall.SIGSYS: "SIGSYS",
}
