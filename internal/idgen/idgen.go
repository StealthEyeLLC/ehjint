// Package idgen creates cryptographically random typed EHJINT identifiers.
package idgen

import (
	"fmt"
	"io"

	"github.com/StealthEyeLLC/ehjint/internal/contracts"
)

const entropyBytes = 16

// New creates a typed random identifier through the canonical contracts implementation.
func New(kind contracts.IDKind) (string, error) {
	identifier, err := contracts.NewIdentifier(kind)
	if err != nil {
		return "", err
	}
	return identifier.String(), nil
}

// FromReader exists for deterministic tests; production callers use New.
func FromReader(kind contracts.IDKind, reader io.Reader) (string, error) {
	if reader == nil {
		return "", fmt.Errorf("identifier entropy reader is required")
	}
	identifier, err := contracts.NewIdentifierFrom(kind, reader)
	if err != nil {
		return "", err
	}
	return identifier.String(), nil
}
