package registry

import (
	"encoding/json"
	"strings"
	"testing"
)

func parsedGeneratedSource(t *testing.T) Source {
	t.Helper()
	var source Source
	if err := json.Unmarshal([]byte(generatedRegistryJSON), &source); err != nil {
		t.Fatal(err)
	}
	return source
}

func marshalSource(t *testing.T, source Source) []byte {
	t.Helper()
	data, err := json.Marshal(source)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func TestCompiledCatalogIdentityAndOrdering(t *testing.T) {
	catalog := Compiled()
	if catalog.Digest() != GeneratedRegistryDigest || catalog.SchemaVersion() != 1 {
		t.Fatalf("compiled catalog identity mismatch: digest=%s version=%d", catalog.Digest(), catalog.SchemaVersion())
	}
	operations := catalog.List()
	if len(operations) != 6 {
		t.Fatalf("operation count = %d", len(operations))
	}
	for index := 1; index < len(operations); index++ {
		if operations[index-1].Name >= operations[index].Name {
			t.Fatalf("operations are not lexically ordered: %q >= %q", operations[index-1].Name, operations[index].Name)
		}
	}

	operations[0].Name = "mutated"
	operations[0].ErrorCodes[0] = "mutated"
	fresh := catalog.List()
	if fresh[0].Name == "mutated" || fresh[0].ErrorCodes[0] == "mutated" {
		t.Fatal("catalog list leaked mutable internal state")
	}
	described, ok := catalog.Describe("system.version")
	if !ok {
		t.Fatal("system.version missing")
	}
	described.CLI.Path[0] = "mutated"
	freshDescription, _ := catalog.Describe("system.version")
	if freshDescription.CLI.Path[0] == "mutated" {
		t.Fatal("catalog description leaked mutable internal state")
	}
}

func TestRegistryDigestIndependentOfSourceOrdering(t *testing.T) {
	source := parsedGeneratedSource(t)
	for left, right := 0, len(source.Operations)-1; left < right; left, right = left+1, right-1 {
		source.Operations[left], source.Operations[right] = source.Operations[right], source.Operations[left]
	}
	parsed, digest, err := ParseSource(marshalSource(t, source))
	if err != nil {
		t.Fatal(err)
	}
	if digest != GeneratedRegistryDigest || parsed.Operations[0].Name != "machine.create" {
		t.Fatalf("normalization drift: digest=%s first=%s", digest, parsed.Operations[0].Name)
	}
}

func TestRegistryContradictionsFailClosed(t *testing.T) {
	tests := map[string]func(*Source){
		"duplicate semantic name": func(source *Source) {
			source.Operations[1].Name = source.Operations[0].Name
		},
		"duplicate CLI path": func(source *Source) {
			source.Operations[1].CLI.Path = append([]string(nil), source.Operations[0].CLI.Path...)
		},
		"mutating without idempotency": func(source *Source) {
			source.Operations[0].Classification = "mutating"
			source.Operations[0].Idempotency = "none"
		},
		"MCP divergence": func(source *Source) {
			source.Operations[0].MCP.Operation = "system.version"
		},
		"streaming contradiction": func(source *Source) {
			source.Operations[0].Streaming = "resumable"
			source.Operations[0].ResultMode = "single"
		},
		"unknown fields accepted": func(source *Source) {
			source.Operations[0].UnknownFields = "ignore"
		},
		"CLI argument missing from schema": func(source *Source) {
			source.Operations[0].CLI.Arguments[0].Name = "missing"
		},
		"CLI requiredness drift": func(source *Source) {
			source.Operations[0].CLI.Arguments[0].Required = false
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			source := parsedGeneratedSource(t)
			mutate(&source)
			if _, _, err := ParseSource(marshalSource(t, source)); err == nil {
				t.Fatal("invalid registry source accepted")
			}
		})
	}
	unknownTopLevel := strings.Replace(generatedRegistryJSON, `"schema_version":1`, `"schema_version":1,"unexpected":true`, 1)
	if _, _, err := ParseSource([]byte(unknownTopLevel)); err == nil {
		t.Fatal("unknown registry source field accepted")
	}
}

func TestRegistryDerivedCLIResolution(t *testing.T) {
	catalog := Compiled()
	operation, input, err := catalog.ResolveCLI([]string{"registry", "describe", "system.version"})
	if err != nil {
		t.Fatal(err)
	}
	if operation.Name != "registry.describe" || input["operation"] != "system.version" {
		t.Fatalf("unexpected CLI resolution: operation=%q input=%v", operation.Name, input)
	}

	create, createInput, err := catalog.ResolveCLI([]string{"machine", "create", "test-machine", "2", "512", "4"})
	if err != nil {
		t.Fatal(err)
	}
	if create.Name != "machine.create" || createInput["name"] != "test-machine" || createInput["vcpus"] != int64(2) || createInput["memory_mib"] != int64(512) || createInput["root_disk_gib"] != int64(4) {
		t.Fatalf("unexpected machine create CLI resolution: operation=%q input=%#v", create.Name, createInput)
	}
	operation.CLI.Path[0] = "mutated"
	fresh, _, err := catalog.ResolveCLI([]string{"registry", "describe", "system.version"})
	if err != nil || fresh.CLI.Path[0] != "registry" {
		t.Fatal("CLI resolution leaked mutable state")
	}
	for _, arguments := range [][]string{
		{"registry", "describe"},
		{"registry", "list", "extra"},
		{"machine", "start"},
	} {
		if _, _, err := catalog.ResolveCLI(arguments); err == nil {
			t.Fatalf("invalid CLI accepted: %v", arguments)
		}
	}
}
