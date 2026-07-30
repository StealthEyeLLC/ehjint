package machine

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/StealthEyeLLC/ehjint/internal/contracts"
	"github.com/StealthEyeLLC/ehjint/internal/controller"
	"github.com/StealthEyeLLC/ehjint/internal/hostidentity"
	"github.com/StealthEyeLLC/ehjint/internal/layout"
	"github.com/StealthEyeLLC/ehjint/internal/registry"
	"github.com/StealthEyeLLC/ehjint/internal/state"
)

// ControllerConfig is the strict on-disk authority for one isolated EHJINT
// controller instance. No path or digest is inferred from process state.
type ControllerConfig struct {
	SchemaVersion      int    `json:"schema_version"`
	Root               string `json:"root"`
	SocketUID          int    `json:"socket_uid"`
	SocketGID          int    `json:"socket_gid"`
	KVMGID             int    `json:"kvm_gid"`
	ExecutablePath     string `json:"executable_path"`
	ExecutableDigest   string `json:"executable_digest"`
	VMMPath            string `json:"vmm_path"`
	VMMVersion         string `json:"vmm_version"`
	VMMDigest          string `json:"vmm_digest"`
	FirmwarePath       string `json:"firmware_path"`
	FirmwareVersion    string `json:"firmware_version"`
	FirmwareDigest     string `json:"firmware_digest"`
	BaseImagePath      string `json:"base_image_path"`
	BaseImageProduct   string `json:"base_image_product"`
	BaseImageVersion   string `json:"base_image_version"`
	BaseImageDigest    string `json:"base_image_digest"`
	CreatingReleaseID  string `json:"creating_release_id"`
	AgentVersion       string `json:"agent_version"`
	RequestTimeoutSecs int    `json:"request_timeout_seconds"`
	MaxConnections     int    `json:"max_connections"`
}

// LoadControllerConfig performs strict bounded parsing and validates the
// configuration file itself before returning authority.
func LoadControllerConfig(path string) (ControllerConfig, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return ControllerConfig{}, fmt.Errorf("controller config path must be canonical absolute")
	}
	info, err := os.Lstat(path)
	if err != nil {
		return ControllerConfig{}, fmt.Errorf("inspect controller config: %w", err)
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o022 != 0 || info.Size() > 64*1024 {
		return ControllerConfig{}, fmt.Errorf("controller config file is unsafe")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return ControllerConfig{}, fmt.Errorf("read controller config: %w", err)
	}
	var config ControllerConfig
	if err := contracts.DecodeStrict(data, &config); err != nil {
		return ControllerConfig{}, fmt.Errorf("parse controller config: %w", err)
	}
	if err := config.Validate(); err != nil {
		return ControllerConfig{}, err
	}
	return config, nil
}

func (config ControllerConfig) Validate() error {
	if config.SchemaVersion != 1 || config.SocketUID < 0 || config.SocketGID < 0 || config.KVMGID <= 0 {
		return fmt.Errorf("invalid controller identity configuration")
	}
	if !filepath.IsAbs(config.Root) || filepath.Clean(config.Root) != config.Root || config.Root == "/" {
		return fmt.Errorf("controller root must be a non-root canonical absolute path")
	}
	paths := []string{config.ExecutablePath, config.VMMPath, config.FirmwarePath, config.BaseImagePath}
	for _, path := range paths {
		if !filepath.IsAbs(path) || filepath.Clean(path) != path {
			return fmt.Errorf("controller asset path must be canonical absolute")
		}
	}
	for _, digest := range []string{config.ExecutableDigest, config.VMMDigest, config.FirmwareDigest, config.BaseImageDigest} {
		if len(digest) != 64 {
			return fmt.Errorf("controller asset digest is invalid")
		}
		if _, err := hex.DecodeString(digest); err != nil {
			return fmt.Errorf("controller asset digest is invalid")
		}
	}
	if config.VMMVersion != "53.0.0" || config.FirmwareVersion == "" || config.BaseImageProduct != "Ubuntu Minimal" || config.BaseImageVersion == "" || config.AgentVersion == "" {
		return fmt.Errorf("controller runtime versions are incomplete")
	}
	if _, err := contracts.ParseIdentifier(contracts.ReleaseIDKind, config.CreatingReleaseID); err != nil {
		return err
	}
	if config.RequestTimeoutSecs < 1 || config.RequestTimeoutSecs > 3600 || config.MaxConnections < 1 || config.MaxConnections > 256 {
		return fmt.Errorf("controller bounds are invalid")
	}
	return nil
}

// ServeController opens one isolated durable authority and serves until
// cancellation. It never installs a service or changes a production pointer.
func ServeController(ctx context.Context, configPath string) error {
	config, err := LoadControllerConfig(configPath)
	if err != nil {
		return err
	}
	if err := verifyControllerRoot(config.Root); err != nil {
		return err
	}
	if err := hostidentity.AssertTools(); err != nil {
		return err
	}
	for _, asset := range []struct {
		path       string
		digest     string
		executable bool
	}{
		{config.ExecutablePath, config.ExecutableDigest, true},
		{config.VMMPath, config.VMMDigest, true},
		{config.FirmwarePath, config.FirmwareDigest, true},
		{config.BaseImagePath, config.BaseImageDigest, false},
	} {
		if err := verifyControllerAsset(asset.path, asset.digest, asset.executable); err != nil {
			return err
		}
	}
	if err := verifyCloudHypervisorVersion(ctx, config.VMMPath); err != nil {
		return err
	}
	paths := layout.UnderRoot(config.Root)
	for _, directory := range []string{paths.State, paths.Machines, paths.Operations, paths.Run, paths.RuntimeMachines} {
		if err := ensureDirectory(paths.Root, directory, 0o750, 0, config.SocketGID); err != nil {
			return err
		}
	}
	store, err := state.Open(ctx, filepath.Join(paths.State, "controller.sqlite3"))
	if err != nil {
		return err
	}
	defer store.Close()
	manager, err := New(Config{
		Paths: paths, Store: store, IdentityAuthority: hostidentity.Authority{},
		ExecutablePath: config.ExecutablePath, VMMPath: config.VMMPath, VMMVersion: config.VMMVersion, VMMDigest: config.VMMDigest,
		FirmwarePath: config.FirmwarePath, FirmwareVersion: config.FirmwareVersion, FirmwareDigest: config.FirmwareDigest,
		BaseImagePath: config.BaseImagePath, BaseImageProduct: config.BaseImageProduct, BaseImageVersion: config.BaseImageVersion, BaseImageDigest: config.BaseImageDigest,
		CreatingReleaseID: config.CreatingReleaseID, AgentVersion: config.AgentVersion, KVMGID: config.KVMGID,
		Clock: time.Now,
	})
	if err != nil {
		return err
	}
	catalog := registry.Compiled()
	validator := func(name string, version int) error {
		operation, ok := catalog.Describe(name)
		if !ok || operation.Availability != "active" {
			return fmt.Errorf("operation is not active")
		}
		if operation.Version != version {
			return fmt.Errorf("unsupported operation version")
		}
		return nil
	}
	rootOnly := make(map[string]bool)
	for _, operation := range catalog.List() {
		if operation.Availability == "active" {
			rootOnly[operation.Name] = true
		}
	}
	server, err := controller.NewServer(controller.ServerConfig{
		Paths: paths, SocketUID: config.SocketUID, SocketGID: config.SocketGID,
		Policy: controller.Policy{GroupID: config.SocketGID, RootOnly: rootOnly}, Handler: manager,
		ValidateOperation: validator, RequestTimeout: time.Duration(config.RequestTimeoutSecs) * time.Second,
		MaxConnections: config.MaxConnections,
	})
	if err != nil {
		return err
	}
	return server.ListenAndServe(ctx)
}

func verifyControllerRoot(root string) error {
	info, err := os.Lstat(root)
	if err != nil {
		return fmt.Errorf("inspect controller root: %w", err)
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o002 != 0 {
		return fmt.Errorf("controller root is unsafe")
	}
	return nil
}

func verifyControllerAsset(path, expected string, executable bool) error {
	info, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("inspect controller asset %s: %w", path, err)
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o022 != 0 || (executable && info.Mode().Perm()&0o111 == 0) {
		return fmt.Errorf("controller asset is unsafe: %s", path)
	}
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()
	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return err
	}
	if hex.EncodeToString(hash.Sum(nil)) != expected {
		return fmt.Errorf("controller asset digest mismatch: %s", path)
	}
	return nil
}

func verifyCloudHypervisorVersion(ctx context.Context, path string) error {
	checkCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	command := exec.CommandContext(checkCtx, path, "--version")
	command.Env = []string{"PATH=/usr/bin:/bin", "LANG=C", "LC_ALL=C"}
	output, err := command.CombinedOutput()
	if err != nil {
		return fmt.Errorf("query Cloud Hypervisor version: %w", err)
	}
	if strings.TrimSpace(string(output)) != "cloud-hypervisor v53.0" {
		return fmt.Errorf("unexpected Cloud Hypervisor build version")
	}
	return nil
}
