package contracts

import (
	"crypto/rand"
	"encoding/base32"
	"fmt"
	"io"
	"strings"
)

// IDKind identifies one namespace of durable EHJINT identifiers.
type IDKind string

const (
	OperationIDKind      IDKind = "operation"
	MachineIDKind        IDKind = "machine"
	ReleaseIDKind        IDKind = "release"
	SnapshotIDKind       IDKind = "snapshot"
	JobIDKind            IDKind = "job"
	PTYIDKind            IDKind = "pty"
	CapabilityPackIDKind IDKind = "capability_pack"
)

var idPrefixes = map[IDKind]string{
	OperationIDKind:      "op_",
	MachineIDKind:        "mach_",
	ReleaseIDKind:        "rel_",
	SnapshotIDKind:       "snap_",
	JobIDKind:            "job_",
	PTYIDKind:            "pty_",
	CapabilityPackIDKind: "pack_",
}

const encodedIDBytes = 16
const encodedIDLength = 26

var idEncoding = base32.StdEncoding.WithPadding(base32.NoPadding)

// Identifier is a strictly parsed, type-namespaced identifier.
type Identifier struct {
	Kind  IDKind
	Value string
}

func (identifier Identifier) String() string { return identifier.Value }

// NewIdentifier creates a cryptographically random identifier.
func NewIdentifier(kind IDKind) (Identifier, error) {
	return NewIdentifierFrom(kind, rand.Reader)
}

// NewIdentifierFrom permits deterministic testing while production uses crypto/rand.
func NewIdentifierFrom(kind IDKind, source io.Reader) (Identifier, error) {
	prefix, ok := idPrefixes[kind]
	if !ok {
		return Identifier{}, fmt.Errorf("unknown identifier kind %q", kind)
	}
	bytes := make([]byte, encodedIDBytes)
	if _, err := io.ReadFull(source, bytes); err != nil {
		return Identifier{}, fmt.Errorf("generate %s identifier: %w", kind, err)
	}
	value := prefix + strings.ToLower(idEncoding.EncodeToString(bytes))
	return Identifier{Kind: kind, Value: value}, nil
}

// ParseIdentifier requires the expected namespace, lowercase spelling, and exact length.
func ParseIdentifier(kind IDKind, value string) (Identifier, error) {
	prefix, ok := idPrefixes[kind]
	if !ok {
		return Identifier{}, fmt.Errorf("unknown identifier kind %q", kind)
	}
	if len(value) != len(prefix)+encodedIDLength {
		return Identifier{}, fmt.Errorf("invalid %s identifier length", kind)
	}
	if !strings.HasPrefix(value, prefix) || value != strings.ToLower(value) {
		return Identifier{}, fmt.Errorf("invalid %s identifier namespace or case", kind)
	}
	encoded := strings.TrimPrefix(value, prefix)
	decoded, err := idEncoding.DecodeString(strings.ToUpper(encoded))
	if err != nil || len(decoded) != encodedIDBytes {
		return Identifier{}, fmt.Errorf("invalid %s identifier encoding", kind)
	}
	if strings.ToLower(idEncoding.EncodeToString(decoded)) != encoded {
		return Identifier{}, fmt.Errorf("non-canonical %s identifier encoding", kind)
	}
	return Identifier{Kind: kind, Value: value}, nil
}
