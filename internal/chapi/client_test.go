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
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

type unixServer struct {
	path     string
	listener net.Listener
	server   *http.Server
}

func startUnixServer(t *testing.T, handler http.Handler) *unixServer {
	t.Helper()
	path := filepath.Join(t.TempDir(), "api.sock")
	listener, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	server := &http.Server{Handler: handler, ReadHeaderTimeout: time.Second}
	go func() { _ = server.Serve(listener) }()
	return &unixServer{path: path, listener: listener, server: server}
}

func (server *unixServer) close(t *testing.T) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	_ = server.server.Shutdown(ctx)
	_ = server.listener.Close()
}

func sampleConfig() VMConfig {
	return VMConfig{
		CPUs:    CPUConfig{BootVCPUs: 2, MaxVCPUs: 2},
		Memory:  MemoryConfig{Size: 2 * 1024 * 1024 * 1024},
		Payload: PayloadConfig{Firmware: "/var/lib/ehjint/firmware/hypervisor-fw"},
		Disks: []DiskConfig{
			{Path: "/var/lib/ehjint/machines/default/root.qcow2", NumQueues: 1, QueueSize: 128, Sparse: true, ImageType: ImageTypeQCOW2, ID: "root"},
			{Path: "/var/lib/ehjint/machines/default/seed.img", Readonly: true, NumQueues: 1, QueueSize: 128, Sparse: true, ImageType: ImageTypeRaw, ID: "seed"},
		},
		Net: []any{}, Serial: SerialConfig{Mode: ConsoleModeFile, File: "/run/ehjint/machines/default/serial.log"},
		Console:        ConsoleConfig{Mode: ConsoleModeOff},
		Vsock:          &VsockConfig{CID: 1003, Socket: "/run/ehjint/machines/default/vsock.sock", ID: "agent"},
		LandlockEnable: true,
		LandlockRules:  []LandlockRule{{Path: "/var/lib/ehjint/machines/default", Access: "rw"}},
	}
}

func TestLifecycleUsesExactV53RoutesAndPayload(t *testing.T) {
	var mu sync.Mutex
	var calls []string
	handler := http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		mu.Lock()
		calls = append(calls, request.Method+" "+request.URL.Path)
		mu.Unlock()
		if request.Host != "localhost" {
			t.Errorf("Host = %q", request.Host)
		}
		switch request.URL.Path {
		case APIPrefix + "vmm.ping":
			if request.Method != http.MethodGet {
				t.Errorf("ping method = %s", request.Method)
			}
			writer.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(writer, `{"build_version":"v53.0","version":"53.0.0","pid":321,"features":["mshv"]}`)
		case APIPrefix + "vm.create":
			if request.Method != http.MethodPut {
				t.Errorf("create method = %s", request.Method)
			}
			var raw map[string]json.RawMessage
			decoder := json.NewDecoder(request.Body)
			decoder.DisallowUnknownFields()
			if err := decoder.Decode(&raw); err != nil {
				t.Errorf("decode create: %v", err)
			}
			if _, ok := raw["pvpanic"]; !ok {
				t.Error("create request omitted pvpanic")
			}
			if _, bad := raw["pvp\nanic"]; bad {
				t.Error("create request contained malformed pvpanic key")
			}
			var disks []map[string]any
			if err := json.Unmarshal(raw["disks"], &disks); err != nil {
				t.Errorf("decode disks: %v", err)
			}
			if len(disks) != 2 || disks[0]["image_type"] != "Qcow2" || disks[1]["image_type"] != "Raw" {
				t.Errorf("explicit disk image types = %#v", disks)
			}
			var networks []any
			if err := json.Unmarshal(raw["net"], &networks); err != nil || len(networks) != 0 {
				t.Errorf("networking not explicitly empty: %v %#v", err, networks)
			}
			writer.WriteHeader(http.StatusNoContent)
		case APIPrefix + "vm.boot", APIPrefix + "vm.shutdown", APIPrefix + "vm.delete":
			if request.Method != http.MethodPut {
				t.Errorf("lifecycle method = %s", request.Method)
			}
			writer.WriteHeader(http.StatusNoContent)
		case APIPrefix + "vmm.shutdown":
			if request.Method != http.MethodPut {
				t.Errorf("lifecycle method = %s", request.Method)
			}
			writer.WriteHeader(http.StatusOK)
		case APIPrefix + "vm.info":
			if request.Method != http.MethodGet {
				t.Errorf("info method = %s", request.Method)
			}
			writer.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(writer, `{"config":{"payload":{"firmware":"/x"}},"state":"Running","memory_actual_size":2147483648,"device_tree":{}}`)
		default:
			http.NotFound(writer, request)
		}
	})
	server := startUnixServer(t, handler)
	defer server.close(t)
	client, err := New(server.path, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	ping, err := client.Ping(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if ping.Version != ExpectedRuntimeVersion || ping.BuildVersion != ExpectedBuildVersion || ping.PID != 321 {
		t.Fatalf("ping = %+v", ping)
	}
	if err := client.Create(ctx, sampleConfig()); err != nil {
		t.Fatal(err)
	}
	if err := client.Boot(ctx); err != nil {
		t.Fatal(err)
	}
	info, err := client.Info(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if info.State != VMStateRunning {
		t.Fatalf("info = %+v", info)
	}
	if err := client.ShutdownVM(ctx); err != nil {
		t.Fatal(err)
	}
	if err := client.DeleteVM(ctx); err != nil {
		t.Fatal(err)
	}
	if err := client.ShutdownVMM(ctx); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	defer mu.Unlock()
	expected := []string{
		"GET /api/v1/vmm.ping", "PUT /api/v1/vm.create", "PUT /api/v1/vm.boot", "GET /api/v1/vm.info",
		"PUT /api/v1/vm.shutdown", "PUT /api/v1/vm.delete", "PUT /api/v1/vmm.shutdown",
	}
	if fmt.Sprint(calls) != fmt.Sprint(expected) {
		t.Fatalf("calls = %#v", calls)
	}
}

func TestVMConfigRejectsImplicitAndUnsafeDiskOrNetworkConfiguration(t *testing.T) {
	cases := map[string]func(*VMConfig){
		"implicit image type":     func(config *VMConfig) { config.Disks[0].ImageType = "" },
		"unknown image type":      func(config *VMConfig) { config.Disks[0].ImageType = "Unknown" },
		"duplicate path":          func(config *VMConfig) { config.Disks[1].Path = config.Disks[0].Path },
		"network":                 func(config *VMConfig) { config.Net = []any{map[string]any{"tap": "tap0"}} },
		"missing vsock":           func(config *VMConfig) { config.Vsock = nil },
		"low CID":                 func(config *VMConfig) { config.Vsock.CID = 2 },
		"relative disk":           func(config *VMConfig) { config.Disks[0].Path = "root.qcow2" },
		"Landlock without enable": func(config *VMConfig) { config.LandlockEnable = false },
		"both payloads":           func(config *VMConfig) { config.Payload.Kernel = "/kernel" },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			config := sampleConfig()
			mutate(&config)
			if err := config.Validate(); err == nil {
				t.Fatal("invalid configuration accepted")
			}
		})
	}
}

func TestStrictStatusJSONBoundsTimeoutAndSocketType(t *testing.T) {
	t.Run("bad status", func(t *testing.T) {
		server := startUnixServer(t, http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
			writer.WriteHeader(http.StatusBadRequest)
			_, _ = writer.Write([]byte("bad\x00 request\n"))
		}))
		defer server.close(t)
		client, _ := New(server.path, time.Second)
		_, err := client.Ping(context.Background())
		var apiError *APIError
		if !errors.As(err, &apiError) || apiError.Status != http.StatusBadRequest || strings.ContainsRune(apiError.Body, '\x00') {
			t.Fatalf("error = %#v %v", apiError, err)
		}
	})
	t.Run("unknown ping field", func(t *testing.T) {
		server := startUnixServer(t, http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
			_, _ = io.WriteString(writer, `{"build_version":"v53.0","version":"53.0.0","future":true}`)
		}))
		defer server.close(t)
		client, _ := New(server.path, time.Second)
		if _, err := client.Ping(context.Background()); err == nil || !strings.Contains(err.Error(), "unknown field") {
			t.Fatalf("error = %v", err)
		}
	})
	t.Run("malformed JSON", func(t *testing.T) {
		server := startUnixServer(t, http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) { _, _ = io.WriteString(writer, `{`) }))
		defer server.close(t)
		client, _ := New(server.path, time.Second)
		if _, err := client.Ping(context.Background()); err == nil || !strings.Contains(err.Error(), "decode") {
			t.Fatalf("error = %v", err)
		}
	})
	t.Run("trailing JSON", func(t *testing.T) {
		server := startUnixServer(t, http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
			_, _ = io.WriteString(writer, `{"version":"v53.0"} {}`)
		}))
		defer server.close(t)
		client, _ := New(server.path, time.Second)
		if _, err := client.Ping(context.Background()); err == nil || !strings.Contains(err.Error(), "trailing") {
			t.Fatalf("error = %v", err)
		}
	})
	t.Run("wrong version", func(t *testing.T) {
		server := startUnixServer(t, http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
			_, _ = io.WriteString(writer, `{"build_version":"v54.0","version":"54.0.0"}`)
		}))
		defer server.close(t)
		client, _ := New(server.path, time.Second)
		if _, err := client.Ping(context.Background()); err == nil || !strings.Contains(err.Error(), "pinned") {
			t.Fatalf("error = %v", err)
		}
	})
	t.Run("body on 204", func(t *testing.T) {
		server := startUnixServer(t, http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
			writer.WriteHeader(http.StatusNoContent)
			_, _ = writer.Write([]byte("x"))
		}))
		defer server.close(t)
		client, _ := New(server.path, time.Second)
		// net/http discards an illegal 204 body, so test the helper directly as
		// well as the live status path.
		if err := client.Boot(context.Background()); err != nil {
			t.Fatal(err)
		}
		if data, err := readBounded(bytes.NewBufferString("xx"), 1); err == nil || data != nil {
			t.Fatal("oversized no-content body accepted")
		}
	})
	t.Run("oversized JSON", func(t *testing.T) {
		server := startUnixServer(t, http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
			_, _ = writer.Write(bytes.Repeat([]byte("x"), maxResponseBody+1))
		}))
		defer server.close(t)
		client, _ := New(server.path, time.Second)
		if _, err := client.Ping(context.Background()); err == nil || !strings.Contains(err.Error(), "exceeds") {
			t.Fatalf("error = %v", err)
		}
	})
	t.Run("timeout", func(t *testing.T) {
		server := startUnixServer(t, http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
			time.Sleep(100 * time.Millisecond)
			_, _ = io.WriteString(writer, `{"build_version":"v53.0","version":"53.0.0"}`)
		}))
		defer server.close(t)
		client, _ := New(server.path, 20*time.Millisecond)
		if _, err := client.Ping(context.Background()); err == nil {
			t.Fatal("timeout accepted")
		}
	})
	t.Run("socket disappearance", func(t *testing.T) {
		server := startUnixServer(t, http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
			_, _ = io.WriteString(writer, `{"build_version":"v53.0","version":"53.0.0"}`)
		}))
		client, _ := New(server.path, time.Second)
		server.close(t)
		if _, err := client.Ping(context.Background()); err == nil || !strings.Contains(err.Error(), "inspect Cloud Hypervisor API socket") {
			t.Fatalf("error = %v", err)
		}
	})
	t.Run("non socket", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "api.sock")
		if err := os.WriteFile(path, []byte("not a socket"), 0o600); err != nil {
			t.Fatal(err)
		}
		client, _ := New(path, time.Second)
		if _, err := client.Ping(context.Background()); err == nil || !strings.Contains(err.Error(), "real Unix socket") {
			t.Fatalf("error = %v", err)
		}
	})
	t.Run("symlink socket", func(t *testing.T) {
		server := startUnixServer(t, http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
			_, _ = io.WriteString(writer, `{"build_version":"v53.0","version":"53.0.0"}`)
		}))
		defer server.close(t)
		link := filepath.Join(t.TempDir(), "api.sock")
		if err := os.Symlink(server.path, link); err != nil {
			t.Fatal(err)
		}
		client, _ := New(link, time.Second)
		if _, err := client.Ping(context.Background()); err == nil || !strings.Contains(err.Error(), "real Unix socket") {
			t.Fatalf("error = %v", err)
		}
	})
}

func TestVMInfoStrictValidation(t *testing.T) {
	cases := []VMInfo{
		{Config: json.RawMessage(`{}`), State: "Unknown"},
		{Config: json.RawMessage(`[]`), State: VMStateRunning},
		{Config: json.RawMessage(`{"x":1} trailing`), State: VMStateRunning},
	}
	for _, info := range cases {
		if err := info.Validate(); err == nil {
			t.Fatalf("invalid info accepted: %+v", info)
		}
	}
}
