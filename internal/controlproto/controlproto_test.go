package controlproto

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/StealthEyeLLC/ehjint/internal/contracts"
)

func validRequest() Request {
	return Request{
		ProtocolVersion:  Version,
		RequestID:        "request-abcdef01",
		Operation:        "machine.create",
		OperationVersion: 1,
		IdempotencyKey:   "create-alpha",
		Input:            json.RawMessage(`{"name":"alpha","cpus":2}`),
	}
}

func TestRequestValidationAndCanonicalDigest(t *testing.T) {
	left := validRequest()
	right := validRequest()
	right.RequestID = "request-different"
	right.IdempotencyKey = "other-key"
	right.Input = json.RawMessage(`{"cpus":2,"name":"alpha"}`)
	leftDigest, err := Digest(left)
	if err != nil {
		t.Fatal(err)
	}
	rightDigest, err := Digest(right)
	if err != nil {
		t.Fatal(err)
	}
	if leftDigest != rightDigest || len(leftDigest) != 64 {
		t.Fatalf("canonical digests differ: %q %q", leftDigest, rightDigest)
	}
	right.Input = json.RawMessage(`{"cpus":4,"name":"alpha"}`)
	changed, err := Digest(right)
	if err != nil || changed == leftDigest {
		t.Fatalf("semantic change did not change digest: %q %v", changed, err)
	}
}

func TestRequestRejectsMalformedTransportTruth(t *testing.T) {
	cases := []Request{validRequest(), validRequest(), validRequest(), validRequest(), validRequest()}
	cases[0].ProtocolVersion = 2
	cases[1].RequestID = "bad"
	cases[2].Operation = "Machine Create"
	cases[3].Input = json.RawMessage(`[]`)
	cases[4].Input = json.RawMessage(`{"name":"a"}{"name":"b"}`)
	for index, request := range cases {
		if err := ValidateRequest(request); err == nil {
			t.Fatalf("case %d accepted", index)
		}
	}
}

func TestResponseValidation(t *testing.T) {
	exit := 37
	publicError := &contracts.ErrorEnvelope{SchemaVersion: 1, Code: contracts.CodeCancelled, Message: "cancelled", Operation: "exec.run", Retryable: false}
	valid := []Response{
		{ProtocolVersion: Version, RequestID: "request-abcdef01", Kind: "accepted", OperationID: "op_aebagbafaydqqcikbmga2dqpca"},
		{ProtocolVersion: Version, RequestID: "request-abcdef01", Kind: "stream", OperationID: "op_aebagbafaydqqcikbmga2dqpca", Sequence: 1, Stream: "stdout", Data: []byte("hello")},
		{ProtocolVersion: Version, RequestID: "request-abcdef01", Kind: "result", Result: json.RawMessage(`{"ok":true}`)},
		{ProtocolVersion: Version, RequestID: "request-abcdef01", Kind: "error", Error: publicError},
		{ProtocolVersion: Version, RequestID: "request-abcdef01", Kind: "end", OperationID: "op_aebagbafaydqqcikbmga2dqpca", ExitStatus: &exit},
	}
	for index, response := range valid {
		if err := ValidateResponse(response); err != nil {
			t.Fatalf("valid response %d rejected: %v", index, err)
		}
	}
	invalid := valid[1]
	invalid.Data = []byte(strings.Repeat("x", MaxStreamPayload+1))
	if err := ValidateResponse(invalid); err == nil {
		t.Fatal("oversized stream response accepted")
	}
	invalid = valid[0]
	invalid.Result = json.RawMessage(`{"bad":true}`)
	if err := ValidateResponse(invalid); err == nil {
		t.Fatal("contradictory accepted response accepted")
	}
}
