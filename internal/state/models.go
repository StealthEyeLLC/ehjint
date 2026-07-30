package state

import (
	"database/sql"
	"fmt"
	"regexp"
	"time"
)

var (
	digestPattern    = regexp.MustCompile(`^[0-9a-f]{64}$`)
	operationPattern = regexp.MustCompile(`^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)+$`)
)

// DesiredState is the controller's durable target.
type DesiredState string

const (
	DesiredRunning DesiredState = "running"
	DesiredStopped DesiredState = "stopped"
	DesiredAbsent  DesiredState = "absent"
)

// ObservedState records re-observed host and guest truth.
type ObservedState string

const (
	ObservedAbsent    ObservedState = "absent"
	ObservedPreparing ObservedState = "preparing"
	ObservedStarting  ObservedState = "starting"
	ObservedRunning   ObservedState = "running"
	ObservedStopping  ObservedState = "stopping"
	ObservedStopped   ObservedState = "stopped"
	ObservedRemoving  ObservedState = "removing"
	ObservedDegraded  ObservedState = "degraded"
	ObservedUnknown   ObservedState = "unknown"
)

// Machine is the compact durable projection. The complete recreation contract
// remains the authoritative manifest file named by ManifestPath.
type Machine struct {
	MachineID            string
	StableName           string
	DesiredState         DesiredState
	ObservedState        ObservedState
	ManifestPath         string
	ManifestDigest       string
	CreatingRelease      string
	VMMVersion           string
	VMMDigest            string
	GuestImageDigest     string
	FirmwareDigest       string
	OverlayIdentity      string
	VsockCID             uint32
	AgentPort            uint32
	VMMIdentity          string
	VMMUID               int
	VMMGID               int
	VMMPID               int
	ProcessStartIdentity string
	APISocket            string
	VsockSocket          string
	GuestBootID          string
	ReadinessState       string
	LastFailure          string
	Generation           int64
	CreatedAt            time.Time
	UpdatedAt            time.Time
}

// MachineSpec contains immutable machine configuration accepted at creation.
type MachineSpec struct {
	MachineID        string
	StableName       string
	ManifestPath     string
	ManifestDigest   string
	CreatingRelease  string
	VMMVersion       string
	VMMDigest        string
	GuestImageDigest string
	FirmwareDigest   string
	OverlayIdentity  string
	VsockCID         uint32
	AgentPort        uint32
	VMMIdentity      string
	VMMUID           int
	VMMGID           int
	APISocket        string
	VsockSocket      string
}

// RuntimeObservation is the process and readiness truth re-observed by the
// controller.
type RuntimeObservation struct {
	VMMPID               int
	ProcessStartIdentity string
	GuestBootID          string
	ReadinessState       string
	LastFailure          string
}

// Operation is one durable public mutation or foreground session identity.
type Operation struct {
	OperationID           string
	OperationName         string
	OperationVersion      int
	IdempotencyKey        string
	RequestDigest         string
	MachineID             string
	State                 string
	CancellationRequested bool
	ResultPath            string
	ErrorCode             string
	ErrorMessage          string
	StdoutPath            string
	StderrPath            string
	StdoutCursor          int64
	StderrCursor          int64
	CreatedAt             time.Time
	UpdatedAt             time.Time
	StartedAt             *time.Time
	FinishedAt            *time.Time
}

// OperationRequest is the complete idempotency identity persisted before any
// mutation.
type OperationRequest struct {
	OperationID      string
	OperationName    string
	OperationVersion int
	IdempotencyKey   string
	RequestDigest    string
	MachineID        string
}

// OperationUpdate contains terminal paths and bounded public failure truth.
type OperationUpdate struct {
	ResultPath   string
	ErrorCode    string
	ErrorMessage string
}

// OwnedResource is the minimum proof required for exact cleanup.
type OwnedResource struct {
	ResourceID int64
	MachineID  string
	Kind       string
	Path       string
	Identity   string
	Digest     string
	UID        *int
	GID        *int
	CreatedAt  time.Time
}

func parseTime(value string) (time.Time, error) {
	parsed, err := time.Parse(time.RFC3339Nano, value)
	if err != nil {
		return time.Time{}, fmt.Errorf("parse durable timestamp %q: %w", value, err)
	}
	return parsed, nil
}

func parseNullableTime(value sql.NullString) (*time.Time, error) {
	if !value.Valid {
		return nil, nil
	}
	parsed, err := parseTime(value.String)
	if err != nil {
		return nil, err
	}
	return &parsed, nil
}

func validDesired(state DesiredState) bool {
	return state == DesiredRunning || state == DesiredStopped || state == DesiredAbsent
}

var observedTransitions = map[ObservedState]map[ObservedState]bool{
	ObservedAbsent:    {ObservedAbsent: true, ObservedPreparing: true, ObservedRemoving: true},
	ObservedPreparing: {ObservedPreparing: true, ObservedStarting: true, ObservedStopped: true, ObservedRemoving: true, ObservedDegraded: true, ObservedAbsent: true},
	ObservedStarting:  {ObservedStarting: true, ObservedRunning: true, ObservedStopped: true, ObservedRemoving: true, ObservedDegraded: true, ObservedUnknown: true},
	ObservedRunning:   {ObservedRunning: true, ObservedStopping: true, ObservedRemoving: true, ObservedDegraded: true, ObservedUnknown: true},
	ObservedStopping:  {ObservedStopping: true, ObservedStopped: true, ObservedRemoving: true, ObservedDegraded: true, ObservedUnknown: true, ObservedAbsent: true},
	ObservedStopped:   {ObservedStopped: true, ObservedStarting: true, ObservedRemoving: true, ObservedAbsent: true, ObservedDegraded: true, ObservedUnknown: true},
	ObservedRemoving:  {ObservedRemoving: true, ObservedAbsent: true, ObservedDegraded: true, ObservedUnknown: true},
	ObservedDegraded:  {ObservedDegraded: true, ObservedPreparing: true, ObservedStarting: true, ObservedRunning: true, ObservedStopping: true, ObservedStopped: true, ObservedRemoving: true, ObservedAbsent: true, ObservedUnknown: true},
	ObservedUnknown:   {ObservedUnknown: true, ObservedAbsent: true, ObservedPreparing: true, ObservedStarting: true, ObservedRunning: true, ObservedStopped: true, ObservedRemoving: true, ObservedDegraded: true},
}

// ValidateObservedTransition rejects undeclared lifecycle movement.
func ValidateObservedTransition(from, to ObservedState) error {
	if !observedTransitions[from][to] {
		return fmt.Errorf("forbidden machine observed-state transition %q -> %q", from, to)
	}
	return nil
}
