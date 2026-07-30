package idgen

import (
	"bytes"
	"errors"
	"testing"

	"github.com/StealthEyeLLC/ehjint/internal/contracts"
)

type failingReader struct{}

func (failingReader) Read([]byte) (int, error) { return 0, errors.New("entropy unavailable") }

func TestFromReaderProducesCanonicalTypedIdentifier(t *testing.T) {
	identifier, err := FromReader(contracts.OperationIDKind, bytes.NewReader(make([]byte, entropyBytes)))
	if err != nil {
		t.Fatal(err)
	}
	if identifier != "op_aaaaaaaaaaaaaaaaaaaaaaaaaa" {
		t.Fatalf("identifier = %q", identifier)
	}
	if _, err := contracts.ParseIdentifier(contracts.OperationIDKind, identifier); err != nil {
		t.Fatal(err)
	}
}

func TestFromReaderRejectsMissingEntropy(t *testing.T) {
	if _, err := FromReader(contracts.MachineIDKind, failingReader{}); err == nil {
		t.Fatal("entropy failure accepted")
	}
}
