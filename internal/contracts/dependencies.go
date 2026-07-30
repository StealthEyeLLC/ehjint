package contracts

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"regexp"
	"sort"
	"strings"
)

var dependencyDigestPattern = regexp.MustCompile(`^(sha256:[0-9a-f]{64}|git:[0-9a-f]{40})$`)

// DependencyLock is the complete strict lock for dependencies actually used by Mission 1.
type DependencyLock struct {
	SchemaVersion int          `json:"schema_version"`
	Dependencies  []Dependency `json:"dependencies"`
}

// Dependency records source, verification, scope, and licensing for one actual dependency.
type Dependency struct {
	Name            string   `json:"name"`
	Purpose         string   `json:"purpose"`
	Version         string   `json:"version"`
	Source          string   `json:"source"`
	Digest          string   `json:"digest"`
	License         string   `json:"license"`
	LicenseSource   string   `json:"license_source"`
	Scope           string   `json:"scope"`
	Distributed     bool     `json:"distributed"`
	TargetPlatforms []string `json:"target_platforms"`
	Verification    string   `json:"verification"`
}

// ToolchainLock pins the bootstrap archive before any Go program is available.
type ToolchainLock struct {
	SchemaVersion int             `json:"schema_version"`
	Go            GoToolchainLock `json:"go"`
}

// GoToolchainLock describes the official Go archive selected for the reference host.
type GoToolchainLock struct {
	Version       string `json:"version"`
	Target        string `json:"target"`
	Archive       string `json:"archive"`
	URL           string `json:"url"`
	SHA256        string `json:"sha256"`
	License       string `json:"license"`
	LicenseSource string `json:"license_source"`
}

// ParseDependencyLock validates every required field and returns lexical ordering.
func ParseDependencyLock(data []byte) (DependencyLock, error) {
	var lock DependencyLock
	if err := DecodeStrict(data, &lock); err != nil {
		return DependencyLock{}, err
	}
	if lock.SchemaVersion != 1 {
		return DependencyLock{}, fmt.Errorf("unsupported dependency lock version %d", lock.SchemaVersion)
	}
	if len(lock.Dependencies) == 0 {
		return DependencyLock{}, fmt.Errorf("dependency lock is empty")
	}
	seen := make(map[string]bool, len(lock.Dependencies))
	for index, dependency := range lock.Dependencies {
		if dependency.Name == "" || dependency.Purpose == "" || dependency.Version == "" {
			return DependencyLock{}, fmt.Errorf("dependency %d: name, purpose, and version are required", index)
		}
		if seen[dependency.Name] {
			return DependencyLock{}, fmt.Errorf("duplicate dependency %q", dependency.Name)
		}
		seen[dependency.Name] = true
		if !strings.HasPrefix(dependency.Source, "https://") {
			return DependencyLock{}, fmt.Errorf("dependency %q: official HTTPS source is required", dependency.Name)
		}
		if !dependencyDigestPattern.MatchString(dependency.Digest) {
			return DependencyLock{}, fmt.Errorf("dependency %q: invalid source digest", dependency.Name)
		}
		if dependency.License == "" || !strings.HasPrefix(dependency.LicenseSource, "https://") {
			return DependencyLock{}, fmt.Errorf("dependency %q: license and HTTPS license source are required", dependency.Name)
		}
		switch dependency.Scope {
		case "build", "test", "build_test", "runtime", "ci":
		default:
			return DependencyLock{}, fmt.Errorf("dependency %q: invalid scope %q", dependency.Name, dependency.Scope)
		}
		if len(dependency.TargetPlatforms) == 0 || dependency.Verification == "" {
			return DependencyLock{}, fmt.Errorf("dependency %q: target platforms and verification are required", dependency.Name)
		}
		for _, target := range dependency.TargetPlatforms {
			if target == "" {
				return DependencyLock{}, fmt.Errorf("dependency %q: empty target platform", dependency.Name)
			}
		}
	}
	sort.Slice(lock.Dependencies, func(i, j int) bool { return lock.Dependencies[i].Name < lock.Dependencies[j].Name })
	return lock, nil
}

// ParseToolchainLock validates the pre-Go bootstrap lock.
func ParseToolchainLock(data []byte) (ToolchainLock, error) {
	var lock ToolchainLock
	if err := DecodeStrict(data, &lock); err != nil {
		return ToolchainLock{}, err
	}
	if lock.SchemaVersion != 1 {
		return ToolchainLock{}, fmt.Errorf("unsupported toolchain lock version %d", lock.SchemaVersion)
	}
	if lock.Go.Version == "" || lock.Go.Target != "linux/amd64" || lock.Go.Archive == "" {
		return ToolchainLock{}, fmt.Errorf("incomplete Go toolchain lock")
	}
	if !strings.HasPrefix(lock.Go.URL, "https://go.dev/dl/") {
		return ToolchainLock{}, fmt.Errorf("Go toolchain URL must use the official go.dev download source")
	}
	if len(lock.Go.SHA256) != 64 {
		return ToolchainLock{}, fmt.Errorf("Go archive SHA-256 must contain 64 lowercase hexadecimal characters")
	}
	if _, err := hex.DecodeString(lock.Go.SHA256); err != nil || lock.Go.SHA256 != strings.ToLower(lock.Go.SHA256) {
		return ToolchainLock{}, fmt.Errorf("invalid Go archive SHA-256")
	}
	if lock.Go.License != "BSD-3-Clause" || !strings.HasPrefix(lock.Go.LicenseSource, "https://go.dev/") {
		return ToolchainLock{}, fmt.Errorf("invalid Go toolchain license record")
	}
	return lock, nil
}

// VerifyToolchainDependencyAgreement proves the bootstrap and complete dependency locks agree.
func VerifyToolchainDependencyAgreement(toolchain ToolchainLock, dependencies DependencyLock) error {
	for _, dependency := range dependencies.Dependencies {
		if dependency.Name != "go" {
			continue
		}
		if dependency.Version != toolchain.Go.Version || dependency.Source != toolchain.Go.URL || dependency.Digest != "sha256:"+toolchain.Go.SHA256 || dependency.License != toolchain.Go.License {
			return fmt.Errorf("Go toolchain and dependency locks disagree")
		}
		return nil
	}
	return fmt.Errorf("dependency lock does not contain Go")
}

// DependencyLockDigest returns the digest of strict canonical lock data.
func DependencyLockDigest(data []byte) (string, error) {
	lock, err := ParseDependencyLock(data)
	if err != nil {
		return "", err
	}
	canonical, err := marshalCanonical(lock)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(canonical)
	return hex.EncodeToString(digest[:]), nil
}
