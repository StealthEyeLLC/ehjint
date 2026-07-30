package contracts_test

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/StealthEyeLLC/ehjint/internal/contracts"
	"github.com/StealthEyeLLC/ehjint/internal/foundation"
)

const (
	encodedZeroID = "aaaaaaaaaaaaaaaaaaaaaaaaaa"
	digestA       = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	digestB       = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	gitObjectA    = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
)

func identifier(prefix string) string { return prefix + encodedZeroID }

func TestStrictJSONAndCanonicalization(t *testing.T) {
	var destination struct {
		Value int `json:"value"`
	}
	if err := contracts.DecodeStrict([]byte(`{"value":1}`), &destination); err != nil || destination.Value != 1 {
		t.Fatalf("strict decode failed: value=%d err=%v", destination.Value, err)
	}
	for _, malformed := range []string{
		`{"value":1,"unknown":true}`,
		`{"value":1} {"value":2}`,
		`{"value":`,
	} {
		if err := contracts.DecodeStrict([]byte(malformed), &destination); err == nil {
			t.Fatalf("DecodeStrict accepted %q", malformed)
		}
	}
	first, err := contracts.CanonicalJSON([]byte(`{"z":2,"a":{"b":1},"n":1.50}`))
	if err != nil {
		t.Fatal(err)
	}
	second, err := contracts.CanonicalJSON([]byte(` { "n": 1.50, "a": {"b":1}, "z":2 } `))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first, second) || string(first) != `{"a":{"b":1},"n":1.50,"z":2}` {
		t.Fatalf("non-canonical JSON: %s != %s", first, second)
	}
}

func TestIdentifierNamespacesAndUniqueness(t *testing.T) {
	zero := bytes.NewReader(make([]byte, 16))
	operationID, err := contracts.NewIdentifierFrom(contracts.OperationIDKind, zero)
	if err != nil {
		t.Fatal(err)
	}
	if operationID.String() != identifier("op_") {
		t.Fatalf("zero identifier = %q", operationID)
	}
	if _, err := contracts.ParseIdentifier(contracts.OperationIDKind, operationID.String()); err != nil {
		t.Fatal(err)
	}
	if _, err := contracts.ParseIdentifier(contracts.MachineIDKind, operationID.String()); err == nil {
		t.Fatal("cross-namespace identifier accepted")
	}
	for _, malformed := range []string{
		"op_" + strings.ToUpper(encodedZeroID),
		"op_short",
		"op_11111111111111111111111111",
	} {
		if _, err := contracts.ParseIdentifier(contracts.OperationIDKind, malformed); err == nil {
			t.Fatalf("malformed identifier accepted: %q", malformed)
		}
	}

	seen := make(map[string]bool, 2048)
	for index := 0; index < 2048; index++ {
		value, err := contracts.NewIdentifier(contracts.JobIDKind)
		if err != nil {
			t.Fatal(err)
		}
		if seen[value.String()] {
			t.Fatalf("duplicate identifier at index %d", index)
		}
		seen[value.String()] = true
	}
}

func TestOperationStateTransitions(t *testing.T) {
	allowed := [][2]contracts.OperationState{
		{contracts.StateAccepted, contracts.StateAccepted},
		{contracts.StateAccepted, contracts.StateRunning},
		{contracts.StateAccepted, contracts.StateFailed},
		{contracts.StateAccepted, contracts.StateCancelled},
		{contracts.StateRunning, contracts.StateSucceeded},
		{contracts.StateRunning, contracts.StateFailed},
		{contracts.StateRunning, contracts.StateCancelled},
	}
	for _, transition := range allowed {
		if err := contracts.ValidateTransition(transition[0], transition[1]); err != nil {
			t.Fatalf("allowed transition %q -> %q rejected: %v", transition[0], transition[1], err)
		}
	}
	for _, transition := range [][2]contracts.OperationState{
		{contracts.StateSucceeded, contracts.StateRunning},
		{contracts.StateFailed, contracts.StateAccepted},
		{contracts.StateCancelled, contracts.StateRunning},
		{contracts.StateRunning, contracts.StateAccepted},
		{"invented", contracts.StateFailed},
	} {
		if err := contracts.ValidateTransition(transition[0], transition[1]); err == nil {
			t.Fatalf("forbidden transition %q -> %q accepted", transition[0], transition[1])
		}
	}
	if !contracts.StateSucceeded.Terminal() || contracts.StateRunning.Terminal() {
		t.Fatal("terminal state classification is incorrect")
	}
}

func TestResultAndErrorEnvelopesFailClosed(t *testing.T) {
	success := contracts.ResultEnvelope{
		SchemaVersion:    1,
		Operation:        "system.test",
		OperationVersion: 1,
		OperationID:      identifier("op_"),
		State:            contracts.StateSucceeded,
		Result:           json.RawMessage(`{"ok":true}`),
	}
	if err := contracts.ValidateResultEnvelope(success); err != nil {
		t.Fatalf("valid success rejected: %v", err)
	}
	failureError := contracts.ErrorEnvelope{
		SchemaVersion: 1,
		Code:          contracts.CodeFailedPrecondition,
		Message:       "not ready",
		Operation:     "system.test",
		OperationID:   identifier("op_"),
		Retryable:     false,
	}
	failure := success
	failure.State = contracts.StateFailed
	failure.Result = nil
	failure.Error = &failureError
	if err := contracts.ValidateResultEnvelope(failure); err != nil {
		t.Fatalf("valid failure rejected: %v", err)
	}
	invalid := []contracts.ResultEnvelope{
		{SchemaVersion: 1, Operation: "system.test", OperationVersion: 1, State: contracts.StateSucceeded},
		{SchemaVersion: 1, Operation: "system.test", OperationVersion: 1, State: contracts.StateRunning, Result: json.RawMessage(`{}`)},
		{SchemaVersion: 1, Operation: "system.test", OperationVersion: 1, State: contracts.StateFailed},
		{SchemaVersion: 1, Operation: "system.test", OperationVersion: 1, State: contracts.StateSucceeded, Result: json.RawMessage(`{}`), Error: &failureError},
	}
	for index, envelope := range invalid {
		if err := contracts.ValidateResultEnvelope(envelope); err == nil {
			t.Fatalf("invalid result envelope %d accepted", index)
		}
	}
	if status := contracts.ExitStatus(contracts.CodeCancelled); status != 130 {
		t.Fatalf("cancelled exit status = %d", status)
	}
}

func TestIdempotencySemanticBinding(t *testing.T) {
	first, err := contracts.RequestDigest("machine.create", 1, []byte(`{"name":"m","cpu":2}`))
	if err != nil {
		t.Fatal(err)
	}
	second, err := contracts.RequestDigest("machine.create", 1, []byte(` { "cpu": 2, "name": "m" } `))
	if err != nil {
		t.Fatal(err)
	}
	if first != second || len(first) != 64 {
		t.Fatalf("canonical request digests differ: %q %q", first, second)
	}
	candidate := identifier("op_")
	decision, operationID, publicError := contracts.EvaluateIdempotency(nil, "request-0001", first, candidate)
	if publicError != nil || decision != contracts.IdempotencyCreate || operationID != candidate {
		t.Fatalf("unexpected create decision: %q %q %+v", decision, operationID, publicError)
	}
	record := &contracts.IdempotencyRecord{Key: "request-0001", RequestDigest: first, OperationID: candidate}
	decision, operationID, publicError = contracts.EvaluateIdempotency(record, "request-0001", first, identifier("op_"))
	if publicError != nil || decision != contracts.IdempotencyReplay || operationID != candidate {
		t.Fatalf("unexpected replay decision: %q %q %+v", decision, operationID, publicError)
	}
	other, err := contracts.RequestDigest("machine.create", 1, []byte(`{"name":"other"}`))
	if err != nil {
		t.Fatal(err)
	}
	_, _, publicError = contracts.EvaluateIdempotency(record, "request-0001", other, candidate)
	if publicError == nil || publicError.Code != contracts.CodeIdempotencyConflict || publicError.Retryable {
		t.Fatalf("expected non-retryable idempotency conflict, got %+v", publicError)
	}
	corrupt := *record
	corrupt.OperationID = "op_invalid"
	_, _, publicError = contracts.EvaluateIdempotency(&corrupt, "request-0001", first, candidate)
	if publicError == nil || publicError.Code != contracts.CodeInternal {
		t.Fatalf("corrupt record did not fail internally: %+v", publicError)
	}
}

func validMachineManifest() contracts.MachineManifest {
	component := contracts.ComponentBinding{Provider: "reference", Version: "1.0.0", Digest: digestA}
	return contracts.MachineManifest{
		SchemaVersion:     1,
		MachineID:         identifier("mach_"),
		Name:              "mission-one",
		Architecture:      "x86_64",
		VMM:               component,
		Firmware:          component,
		GuestImage:        component,
		GuestAgentVersion: "1.0.0",
		CPU:               contracts.CPUConfiguration{VCPUs: 2, Mode: "generic"},
		Memory:            contracts.MemoryConfiguration{Bytes: 512 * 1024 * 1024, HugePages: false},
		Disks: []contracts.DiskBinding{{
			ID: "root", Role: "root", Format: "raw", BaseDigest: digestA, OverlayID: "root-overlay",
		}},
		Network: contracts.NetworkTopology{
			Mode:       "automatic_nat",
			Interfaces: []contracts.NetworkInterfaceBinding{{Name: "eth0", Model: "virtio"}},
		},
		Devices:                  []contracts.DeviceBinding{},
		CapabilityPacks:          []string{},
		Workspace:                contracts.WorkspaceBinding{Mode: "contained", References: []string{}},
		SnapshotLineage:          contracts.SnapshotLineage{ParentSnapshotID: "", Generation: 0},
		RequiredHostCapabilities: []string{"kvm"},
		CreatingReleaseID:        identifier("rel_"),
	}
}

func TestMachineManifestStrictness(t *testing.T) {
	manifest := validMachineManifest()
	data, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := contracts.ParseMachineManifest(data); err != nil {
		t.Fatalf("valid machine manifest rejected: %v", err)
	}

	cases := map[string]func(*contracts.MachineManifest){
		"missing disk format":    func(value *contracts.MachineManifest) { value.Disks[0].Format = "" },
		"unknown disk format":    func(value *contracts.MachineManifest) { value.Disks[0].Format = "vhdx" },
		"two root disks":         func(value *contracts.MachineManifest) { value.Disks = append(value.Disks, value.Disks[0]) },
		"network contradiction":  func(value *contracts.MachineManifest) { value.Network.Mode = "none" },
		"snapshot contradiction": func(value *contracts.MachineManifest) { value.SnapshotLineage.Generation = 1 },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			value := validMachineManifest()
			mutate(&value)
			data, err := json.Marshal(value)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := contracts.ParseMachineManifest(data); err == nil {
				t.Fatalf("invalid machine manifest accepted: %s", data)
			}
		})
	}

	var object map[string]any
	if err := json.Unmarshal(data, &object); err != nil {
		t.Fatal(err)
	}
	object["unexpected"] = true
	unknown, _ := json.Marshal(object)
	if _, err := contracts.ParseMachineManifest(unknown); err == nil {
		t.Fatal("machine manifest with unknown field accepted")
	}
}

func compatibilityMap() map[string]int {
	return map[string]int{
		"dependency_lock": 1, "error_envelope": 1, "idempotency": 1,
		"input_output_schema": 1, "machine_manifest": 1, "operation_catalog": 1,
		"operation_registry_source": 1, "provider_contract": 1,
		"release_manifest": 1, "result_envelope": 1,
	}
}

func validReleaseManifest() contracts.ReleaseManifest {
	return contracts.ReleaseManifest{
		SchemaVersion:        1,
		ReleaseID:            identifier("rel_"),
		ProductVersion:       "0.0.0-dev",
		SourceCommit:         gitObjectA,
		SourceTree:           gitObjectA,
		BuildMode:            "development",
		Target:               contracts.BuildTarget{OS: "linux", Arch: "amd64"},
		GoToolchain:          contracts.GoToolchainIdentity{Version: "go1.26.5", ArchiveSHA256: digestA},
		RegistryDigest:       digestA,
		BinaryDigest:         digestB,
		Components:           []contracts.ReleaseComponent{},
		Compatibility:        compatibilityMap(),
		DependencyLockDigest: digestA,
		GuestCompatibility:   []string{"guest-agent-contract-v1"},
		VMMCompatibility:     []string{"vmm-contract-v1"},
		Provenance: contracts.BuildProvenance{
			BuilderKind: "local_reproducible", SourceDateEpoch: 1, Reproducible: true,
		},
	}
}

func TestReleaseManifestExactIdentity(t *testing.T) {
	manifest := validReleaseManifest()
	data, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := contracts.ParseReleaseManifest(data); err != nil {
		t.Fatalf("valid release manifest rejected: %v", err)
	}
	manifest.SourceCommit = "short"
	data, _ = json.Marshal(manifest)
	if _, err := contracts.ParseReleaseManifest(data); err == nil {
		t.Fatal("release manifest accepted non-exact source commit")
	}
	manifest = validReleaseManifest()
	delete(manifest.Compatibility, "idempotency")
	data, _ = json.Marshal(manifest)
	if _, err := contracts.ParseReleaseManifest(data); err == nil {
		t.Fatal("release manifest accepted incomplete compatibility")
	}
}

func TestEmbeddedLocksAndProviderContracts(t *testing.T) {
	compatibility, err := contracts.ParseCompatibility([]byte(foundation.CompatibilityJSON))
	if err != nil || len(compatibility.Contracts) != 10 {
		t.Fatalf("compatibility parse: count=%d err=%v", len(compatibility.Contracts), err)
	}
	dependencies, err := contracts.ParseDependencyLock([]byte(foundation.DependencyLockJSON))
	if err != nil {
		t.Fatal(err)
	}
	toolchain, err := contracts.ParseToolchainLock([]byte(foundation.ToolchainLockJSON))
	if err != nil {
		t.Fatal(err)
	}
	if err := contracts.VerifyToolchainDependencyAgreement(toolchain, dependencies); err != nil {
		t.Fatal(err)
	}
	providers, err := contracts.ParseProviderContracts([]byte(foundation.ProviderContractsJSON))
	if err != nil || len(providers.Contracts) != 8 {
		t.Fatalf("providers parse: count=%d err=%v", len(providers.Contracts), err)
	}
	digest, err := contracts.DependencyLockDigest([]byte(foundation.DependencyLockJSON))
	if err != nil || len(digest) != 64 {
		t.Fatalf("dependency digest: %q err=%v", digest, err)
	}
}
