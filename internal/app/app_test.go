package app

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/StealthEyeLLC/ehjint/internal/contracts"
	"github.com/StealthEyeLLC/ehjint/internal/registry"
	"github.com/StealthEyeLLC/ehjint/internal/version"
)

func runJSON(t *testing.T, argv0 string, args ...string) (int, []byte, []byte) {
	t.Helper()
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	arguments := append(args, "--json")
	code := Run(argv0, arguments, &stdout, &stderr)
	return code, stdout.Bytes(), stderr.Bytes()
}

func TestVersionJSON(t *testing.T) {
	code, stdout, stderr := runJSON(t, "ehjint", "version")
	if code != 0 {
		t.Fatalf("Run() code = %d, stderr = %q", code, stderr)
	}
	var got VersionResult
	if err := json.Unmarshal(stdout, &got); err != nil {
		t.Fatalf("version JSON: %v", err)
	}
	if got.Product != version.Product || got.ProductVersion != version.ProductVersion {
		t.Fatalf("unexpected product identity: %+v", got)
	}
	if got.RegistryDigest != registry.GeneratedRegistryDigest || got.Invocation != "ehjint" {
		t.Fatalf("unexpected version registry or invocation: %+v", got)
	}
	if len(got.Compatibility) != 10 {
		t.Fatalf("compatibility count = %d", len(got.Compatibility))
	}
}

func TestAliasParity(t *testing.T) {
	code, primaryOutput, primaryError := runJSON(t, "ehjint", "version")
	if code != 0 {
		t.Fatalf("primary code = %d, stderr = %q", code, primaryError)
	}
	code, aliasOutput, aliasError := runJSON(t, "ej", "version")
	if code != 0 {
		t.Fatalf("alias code = %d, stderr = %q", code, aliasError)
	}
	var primary VersionResult
	var alias VersionResult
	if err := json.Unmarshal(primaryOutput, &primary); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(aliasOutput, &alias); err != nil {
		t.Fatal(err)
	}
	if primary.Invocation != "ehjint" || alias.Invocation != "ej" {
		t.Fatalf("unexpected invocations: %q %q", primary.Invocation, alias.Invocation)
	}
	primary.Invocation = ""
	alias.Invocation = ""
	primaryJSON, _ := json.Marshal(primary)
	aliasJSON, _ := json.Marshal(alias)
	if !bytes.Equal(primaryJSON, aliasJSON) {
		t.Fatalf("alias semantic drift:\nprimary=%s\nalias=%s", primaryJSON, aliasJSON)
	}
}

func TestRegistryListAndDescribe(t *testing.T) {
	code, stdout, stderr := runJSON(t, "ehjint", "registry", "list")
	if code != 0 {
		t.Fatalf("list code = %d, stderr = %q", code, stderr)
	}
	var list RegistryListResult
	if err := json.Unmarshal(stdout, &list); err != nil {
		t.Fatal(err)
	}
	if len(list.Operations) != 4 || list.Operations[0].Name != "registry.describe" {
		t.Fatalf("unexpected operation list: %+v", list.Operations)
	}

	code, stdout, stderr = runJSON(t, "ehjint", "registry", "describe", "system.version")
	if code != 0 {
		t.Fatalf("describe code = %d, stderr = %q", code, stderr)
	}
	var describe RegistryDescribeResult
	if err := json.Unmarshal(stdout, &describe); err != nil {
		t.Fatal(err)
	}
	if describe.Operation.Name != "system.version" || strings.Join(describe.Operation.CLIPath, " ") != "version" || describe.Operation.MCPTool != "ehjint" {
		t.Fatalf("unexpected description: %+v", describe.Operation)
	}
}

func TestDoctorReportsFoundationOnly(t *testing.T) {
	code, stdout, stderr := runJSON(t, "ej", "doctor")
	if code != 0 {
		t.Fatalf("doctor code = %d, stderr = %q", code, stderr)
	}
	var diagnostic DiagnosticResult
	if err := json.Unmarshal(stdout, &diagnostic); err != nil {
		t.Fatal(err)
	}
	if !diagnostic.Healthy || !diagnostic.FoundationOnly || diagnostic.LaterRuntimeActivated || !diagnostic.Alias {
		t.Fatalf("unexpected diagnostic: %+v", diagnostic)
	}
}

func TestBareInvocationFailsClosed(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := Run("ej", nil, &stdout, &stderr)
	if code != contracts.ExitStatus(contracts.CodeFailedPrecondition) {
		t.Fatalf("Run() code = %d", code)
	}
	if stdout.Len() != 0 || !strings.Contains(stderr.String(), "Mission 1 provides diagnostics only") {
		t.Fatalf("stdout=%q stderr=%q", stdout.String(), stderr.String())
	}
}

func TestUnknownCommandUsesStableEnvelope(t *testing.T) {
	code, stdout, stderr := runJSON(t, "ehjint", "machine", "start")
	if code != contracts.ExitStatus(contracts.CodeUnknownOperation) || len(stdout) != 0 {
		t.Fatalf("code=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
	var envelope contracts.ErrorEnvelope
	if err := json.Unmarshal(stderr, &envelope); err != nil {
		t.Fatal(err)
	}
	if envelope.Code != contracts.CodeUnknownOperation || envelope.Operation != "system.dispatch" || envelope.Retryable {
		t.Fatalf("unexpected envelope: %+v", envelope)
	}
}

func TestDuplicateJSONFlagRejected(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := Run("ehjint", []string{"version", "--json", "--json"}, &stdout, &stderr)
	if code != contracts.ExitStatus(contracts.CodeInvalidArgument) {
		t.Fatalf("code=%d stderr=%q", code, stderr.String())
	}
}

func TestInternalGuestAgentInvocationFailsClosed(t *testing.T) {
	cases := [][]string{
		{"internal"},
		{"internal", "guest-agent"},
		{"internal", "guest-agent", "--config", "relative.json"},
		{"internal", "unknown", "--config", "/etc/ehjint/guest-agent.json"},
	}
	for _, arguments := range cases {
		t.Run(strings.Join(arguments, "_"), func(t *testing.T) {
			var stdout bytes.Buffer
			var stderr bytes.Buffer
			code := Run("ehjint", arguments, &stdout, &stderr)
			if code != contracts.ExitStatus(contracts.CodeInvalidArgument) || stdout.Len() != 0 || !strings.Contains(stderr.String(), "internal guest-agent invocation requires") {
				t.Fatalf("code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
			}
		})
	}
}
