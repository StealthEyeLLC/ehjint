package chapi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"time"
)

const (
	defaultTimeout    = 5 * time.Second
	maxResponseBody   = 4 * 1024 * 1024
	maxErrorBody      = 16 * 1024
	maxResponseHeader = 64 * 1024
)

type Client struct {
	socketPath string
	http       *http.Client
}

type APIError struct {
	Method string
	Path   string
	Status int
	Body   string
}

func (failure *APIError) Error() string {
	if failure.Body == "" {
		return fmt.Sprintf("Cloud Hypervisor %s %s returned HTTP %d", failure.Method, failure.Path, failure.Status)
	}
	return fmt.Sprintf("Cloud Hypervisor %s %s returned HTTP %d: %s", failure.Method, failure.Path, failure.Status, failure.Body)
}

func New(socketPath string, timeout time.Duration) (*Client, error) {
	if !canonicalAbsolute(socketPath) || len(socketPath) >= 108 {
		return nil, fmt.Errorf("Cloud Hypervisor API socket path is invalid or too long")
	}
	if timeout <= 0 {
		timeout = defaultTimeout
	}
	dialer := &net.Dialer{Timeout: timeout}
	transport := &http.Transport{
		DisableKeepAlives:      true,
		MaxIdleConns:           0,
		MaxResponseHeaderBytes: maxResponseHeader,
		ResponseHeaderTimeout:  timeout,
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			info, err := os.Lstat(socketPath)
			if err != nil {
				return nil, fmt.Errorf("inspect Cloud Hypervisor API socket: %w", err)
			}
			if info.Mode()&os.ModeSymlink != 0 || info.Mode()&os.ModeSocket == 0 {
				return nil, fmt.Errorf("Cloud Hypervisor API path is not a real Unix socket")
			}
			connection, err := dialer.DialContext(ctx, "unix", socketPath)
			if err != nil {
				return nil, fmt.Errorf("connect Cloud Hypervisor API socket: %w", err)
			}
			return connection, nil
		},
	}
	return &Client{socketPath: socketPath, http: &http.Client{Transport: transport, Timeout: timeout}}, nil
}

func (client *Client) Ping(ctx context.Context) (VMMInfo, error) {
	var response VMMInfo
	if err := client.json(ctx, http.MethodGet, "vmm.ping", nil, http.StatusOK, &response); err != nil {
		return VMMInfo{}, err
	}
	if err := response.Validate(); err != nil {
		return VMMInfo{}, err
	}
	return response, nil
}

func (client *Client) Create(ctx context.Context, config VMConfig) error {
	if err := config.Validate(); err != nil {
		return err
	}
	return client.noContent(ctx, http.MethodPut, "vm.create", config, http.StatusNoContent)
}

func (client *Client) Boot(ctx context.Context) error {
	return client.noContent(ctx, http.MethodPut, "vm.boot", nil, http.StatusNoContent)
}

func (client *Client) Info(ctx context.Context) (VMInfo, error) {
	var response VMInfo
	if err := client.json(ctx, http.MethodGet, "vm.info", nil, http.StatusOK, &response); err != nil {
		return VMInfo{}, err
	}
	if err := response.Validate(); err != nil {
		return VMInfo{}, err
	}
	return response, nil
}

func (client *Client) ShutdownVM(ctx context.Context) error {
	return client.noContent(ctx, http.MethodPut, "vm.shutdown", nil, http.StatusNoContent)
}

func (client *Client) DeleteVM(ctx context.Context) error {
	return client.noContent(ctx, http.MethodPut, "vm.delete", nil, http.StatusNoContent)
}

func (client *Client) ShutdownVMM(ctx context.Context) error {
	return client.noContent(ctx, http.MethodPut, "vmm.shutdown", nil, http.StatusOK)
}

func (client *Client) noContent(ctx context.Context, method, command string, body any, expected int) error {
	response, err := client.request(ctx, method, command, body, expected)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	data, err := readBounded(response.Body, 1)
	if err != nil {
		return err
	}
	if len(data) != 0 {
		return fmt.Errorf("Cloud Hypervisor %s returned a body for HTTP %d no-content response", command, expected)
	}
	return nil
}

func (client *Client) json(ctx context.Context, method, command string, body any, expected int, destination any) error {
	response, err := client.request(ctx, method, command, body, expected)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	data, err := readBounded(response.Body, maxResponseBody)
	if err != nil {
		return err
	}
	if len(bytes.TrimSpace(data)) == 0 {
		return fmt.Errorf("Cloud Hypervisor %s returned an empty JSON body", command)
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return fmt.Errorf("decode Cloud Hypervisor %s response: %w", command, err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return fmt.Errorf("Cloud Hypervisor %s response contains trailing JSON", command)
	}
	return nil
}

func (client *Client) request(ctx context.Context, method, command string, body any, expected int) (*http.Response, error) {
	if client == nil || client.http == nil || !validCommand(command) {
		return nil, fmt.Errorf("invalid Cloud Hypervisor API client or command")
	}
	var reader io.Reader
	if body != nil {
		encoded, err := json.Marshal(body)
		if err != nil {
			return nil, fmt.Errorf("encode Cloud Hypervisor %s request: %w", command, err)
		}
		if len(encoded) > maxResponseBody {
			return nil, fmt.Errorf("Cloud Hypervisor %s request exceeds bound", command)
		}
		reader = bytes.NewReader(encoded)
	}
	request, err := http.NewRequestWithContext(ctx, method, "http://localhost"+APIPrefix+command, reader)
	if err != nil {
		return nil, fmt.Errorf("build Cloud Hypervisor %s request: %w", command, err)
	}
	request.Host = "localhost"
	request.Header.Set("Accept", "application/json")
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	response, err := client.http.Do(request)
	if err != nil {
		return nil, fmt.Errorf("Cloud Hypervisor %s request failed: %w", command, err)
	}
	if response.StatusCode != expected {
		defer response.Body.Close()
		data, readErr := readBounded(response.Body, maxErrorBody)
		if readErr != nil {
			return nil, fmt.Errorf("Cloud Hypervisor %s returned HTTP %d and unreadable error body: %w", command, response.StatusCode, readErr)
		}
		return nil, &APIError{Method: method, Path: APIPrefix + command, Status: response.StatusCode, Body: sanitizeBody(data)}
	}
	return response, nil
}

func readBounded(reader io.Reader, limit int64) ([]byte, error) {
	data, err := io.ReadAll(io.LimitReader(reader, limit+1))
	if err != nil {
		return nil, fmt.Errorf("read bounded Cloud Hypervisor response: %w", err)
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("Cloud Hypervisor response exceeds %d-byte bound", limit)
	}
	return data, nil
}

func validCommand(command string) bool {
	switch command {
	case "vmm.ping", "vmm.shutdown", "vm.create", "vm.boot", "vm.info", "vm.shutdown", "vm.delete":
		return true
	default:
		return false
	}
}

func sanitizeBody(data []byte) string {
	value := strings.TrimSpace(string(data))
	value = strings.Map(func(r rune) rune {
		if r == '\n' || r == '\r' || r == '\t' || (r >= 0x20 && r != 0x7f) {
			return r
		}
		return -1
	}, value)
	if len(value) > maxErrorBody {
		value = value[:maxErrorBody]
	}
	return value
}
