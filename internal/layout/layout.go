// Package layout owns the canonical public installation, durable-state, cache,
// and runtime paths used by EHJINT.
package layout

import (
	"fmt"
	"path/filepath"
	"strings"
)

const (
	OptRootCanonical        = "/opt/ehjint"
	CurrentCanonical        = "/opt/ehjint/current"
	BinCanonical            = "/usr/local/bin/ehjint"
	AliasCanonical          = "/usr/local/bin/ej"
	EtcCanonical            = "/etc/ehjint"
	HostConfigCanonical     = "/etc/ehjint/host.json"
	OperatorConfigCanonical = "/etc/ehjint/operator.json"
	StateCanonical          = "/var/lib/ehjint"
	DatabaseCanonical       = "/var/lib/ehjint/controller.sqlite3"
	ImagesCanonical         = "/var/lib/ehjint/images/sha256"
	MachinesCanonical       = "/var/lib/ehjint/machines"
	OperationsCanonical     = "/var/lib/ehjint/operations"
	CacheCanonical          = "/var/cache/ehjint/downloads"
	RunCanonical            = "/run/ehjint"
	ControllerSocket        = "/run/ehjint/controller.sock"
	ControllerLock          = "/run/ehjint/controller.lock"
	RuntimeMachines         = "/run/ehjint/machines"
)

// Paths is a complete path set rooted either at the real host root or at one
// explicit disposable test root.
type Paths struct {
	Root             string
	Opt              string
	Releases         string
	Current          string
	Bin              string
	Alias            string
	Etc              string
	HostConfig       string
	OperatorConfig   string
	State            string
	Database         string
	Images           string
	Machines         string
	Operations       string
	Downloads        string
	Run              string
	ControllerSocket string
	ControllerLock   string
	RuntimeMachines  string
}

// Canonical returns the required real-host layout.
func Canonical() Paths { return UnderRoot("/") }

// UnderRoot maps every canonical absolute path beneath one explicit root. It is
// used for disposable-host installation and deterministic tests, never as an
// implicit environment override.
func UnderRoot(root string) Paths {
	clean := filepath.Clean(root)
	join := func(path string) string {
		return filepath.Join(clean, strings.TrimPrefix(path, string(filepath.Separator)))
	}
	return Paths{
		Root:             clean,
		Opt:              join(OptRootCanonical),
		Releases:         join(OptRootCanonical + "/releases"),
		Current:          join(CurrentCanonical),
		Bin:              join(BinCanonical),
		Alias:            join(AliasCanonical),
		Etc:              join(EtcCanonical),
		HostConfig:       join(HostConfigCanonical),
		OperatorConfig:   join(OperatorConfigCanonical),
		State:            join(StateCanonical),
		Database:         join(DatabaseCanonical),
		Images:           join(ImagesCanonical),
		Machines:         join(MachinesCanonical),
		Operations:       join(OperationsCanonical),
		Downloads:        join(CacheCanonical),
		Run:              join(RunCanonical),
		ControllerSocket: join(ControllerSocket),
		ControllerLock:   join(ControllerLock),
		RuntimeMachines:  join(RuntimeMachines),
	}
}

// Release returns one side-by-side immutable release directory.
func (paths Paths) Release(releaseID string) (string, error) {
	return SafeJoin(paths.Releases, releaseID)
}

// Machine returns one durable machine directory.
func (paths Paths) Machine(machineID string) (string, error) {
	return SafeJoin(paths.Machines, machineID)
}

// Operation returns one durable operation directory.
func (paths Paths) Operation(operationID string) (string, error) {
	return SafeJoin(paths.Operations, operationID)
}

// RuntimeMachine returns one per-boot machine runtime directory.
func (paths Paths) RuntimeMachine(machineID string) (string, error) {
	return SafeJoin(paths.RuntimeMachines, machineID)
}

// Image returns one content-addressed immutable image directory.
func (paths Paths) Image(digest string) (string, error) {
	return SafeJoin(paths.Images, digest)
}

// SafeJoin rejects absolute elements, traversal, NULs, and lexical escapes.
func SafeJoin(root string, elements ...string) (string, error) {
	if !filepath.IsAbs(root) {
		return "", fmt.Errorf("managed root must be absolute")
	}
	cleanRoot := filepath.Clean(root)
	parts := []string{cleanRoot}
	for _, element := range elements {
		if element == "" || filepath.IsAbs(element) || strings.ContainsRune(element, '\x00') {
			return "", fmt.Errorf("unsafe managed path element %q", element)
		}
		clean := filepath.Clean(element)
		if clean == "." || clean == ".." || strings.HasPrefix(clean, ".."+string(filepath.Separator)) {
			return "", fmt.Errorf("unsafe managed path element %q", element)
		}
		parts = append(parts, clean)
	}
	candidate := filepath.Join(parts...)
	if !Within(cleanRoot, candidate) || candidate == cleanRoot {
		return "", fmt.Errorf("managed path escapes or equals root")
	}
	return candidate, nil
}

// Within reports lexical containment after absolute path cleaning.
func Within(root, candidate string) bool {
	cleanRoot := filepath.Clean(root)
	cleanCandidate := filepath.Clean(candidate)
	relative, err := filepath.Rel(cleanRoot, cleanCandidate)
	return err == nil && relative != "." && relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator))
}
