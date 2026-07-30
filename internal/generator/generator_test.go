package generator

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"testing"
)

func repositoryRoot(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(file), "..", ".."))
}

func copyCanonicalInputs(t *testing.T, sourceRoot, destinationRoot string) {
	t.Helper()
	paths := []string{
		"registry/operations.json",
		"config/compatibility.json",
		"config/dependencies.lock.json",
		"config/provider-contracts.json",
		"config/toolchain.lock.json",
	}
	for _, relative := range paths {
		source := filepath.Join(sourceRoot, filepath.FromSlash(relative))
		destination := filepath.Join(destinationRoot, filepath.FromSlash(relative))
		content, err := os.ReadFile(source)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.MkdirAll(filepath.Dir(destination), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(destination, content, 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

func artifactMap(artifacts []Artifact) map[string][]byte {
	result := make(map[string][]byte, len(artifacts))
	for _, artifact := range artifacts {
		result[artifact.Path] = artifact.Content
	}
	return result
}

func TestGenerationDeterministicAcrossIndependentRoots(t *testing.T) {
	sourceRoot := repositoryRoot(t)
	firstRoot := t.TempDir()
	secondRoot := t.TempDir()
	copyCanonicalInputs(t, sourceRoot, firstRoot)
	copyCanonicalInputs(t, sourceRoot, secondRoot)

	firstInputs, err := LoadInputs(firstRoot)
	if err != nil {
		t.Fatal(err)
	}
	secondInputs, err := LoadInputs(secondRoot)
	if err != nil {
		t.Fatal(err)
	}
	firstArtifacts, err := Render(firstInputs)
	if err != nil {
		t.Fatal(err)
	}
	secondArtifacts, err := Render(secondInputs)
	if err != nil {
		t.Fatal(err)
	}
	if len(firstArtifacts) != len(secondArtifacts) || len(firstArtifacts) != 32 {
		t.Fatalf("artifact counts differ: %d %d", len(firstArtifacts), len(secondArtifacts))
	}
	for index := range firstArtifacts {
		first := firstArtifacts[index]
		second := secondArtifacts[index]
		if first.Path != second.Path || !bytes.Equal(first.Content, second.Content) {
			t.Fatalf("non-deterministic artifact at index %d: %q %q", index, first.Path, second.Path)
		}
		privatePath := "/" + "var/lib/"
		privateExecutor := "baby" + "-quirt"
		if bytes.Contains(first.Content, []byte(privatePath)) || bytes.Contains(first.Content, []byte(privateExecutor)) {
			t.Fatalf("generated artifact contains private execution detail: %s", first.Path)
		}
	}
}

func TestGeneratedCheckDetectsTamperingAndUnexpectedFiles(t *testing.T) {
	root := repositoryRoot(t)
	inputs, err := LoadInputs(root)
	if err != nil {
		t.Fatal(err)
	}
	artifacts, err := Render(inputs)
	if err != nil {
		t.Fatal(err)
	}
	outputRoot := t.TempDir()
	if err := Write(outputRoot, artifacts); err != nil {
		t.Fatal(err)
	}
	if err := Check(outputRoot, artifacts); err != nil {
		t.Fatalf("fresh generated output rejected: %v", err)
	}

	tampered := filepath.Join(outputRoot, filepath.FromSlash(artifacts[0].Path))
	if err := os.WriteFile(tampered, []byte("tampered\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := Check(outputRoot, artifacts); err == nil || !strings.Contains(err.Error(), "stale") {
		t.Fatalf("tampering was not detected: %v", err)
	}
	if err := Write(outputRoot, artifacts); err != nil {
		t.Fatal(err)
	}

	unexpected := filepath.Join(outputRoot, "api", "unexpected.json")
	if err := os.WriteFile(unexpected, []byte("{}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := Check(outputRoot, artifacts); err == nil || !strings.Contains(err.Error(), "unexpected file") {
		t.Fatalf("unexpected generated-owned file was not detected: %v", err)
	}
}

func TestTrackedGeneratedArtifactsCurrent(t *testing.T) {
	root := repositoryRoot(t)
	inputs, err := LoadInputs(root)
	if err != nil {
		t.Fatal(err)
	}
	artifacts, err := Render(inputs)
	if err != nil {
		t.Fatal(err)
	}
	if err := Check(root, artifacts); err != nil {
		t.Fatal(err)
	}
}

func TestMalformedRegistryPreventsGeneration(t *testing.T) {
	root := repositoryRoot(t)
	inputRoot := t.TempDir()
	copyCanonicalInputs(t, root, inputRoot)
	path := filepath.Join(inputRoot, "registry", "operations.json")
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	content = bytes.Replace(content, []byte(`"schema_version": 1,`), []byte(`"schema_version": 1, "unexpected": true,`), 1)
	if err := os.WriteFile(path, content, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadInputs(inputRoot); err == nil {
		t.Fatal("malformed registry input did not block generation")
	}
}

func TestGeneratedMCPAndParityCoverCanonicalOperations(t *testing.T) {
	root := repositoryRoot(t)
	inputs, err := LoadInputs(root)
	if err != nil {
		t.Fatal(err)
	}
	artifacts, err := Render(inputs)
	if err != nil {
		t.Fatal(err)
	}
	byPath := artifactMap(artifacts)

	var mcp struct {
		RegistryDigest string `json:"registry_digest"`
		Tools          []struct {
			Name        string `json:"name"`
			InputSchema struct {
				Properties map[string]struct {
					Enum []string `json:"enum"`
				} `json:"properties"`
			} `json:"input_schema"`
		} `json:"tools"`
	}
	if err := json.Unmarshal(byPath["api/mcp-tools.json"], &mcp); err != nil {
		t.Fatal(err)
	}
	if mcp.RegistryDigest != inputs.RegistryDigest || len(mcp.Tools) != 1 || mcp.Tools[0].Name != "ehjint" {
		t.Fatalf("unexpected MCP descriptor: %+v", mcp)
	}
	operationEnum := append([]string(nil), mcp.Tools[0].InputSchema.Properties["operation"].Enum...)
	sort.Strings(operationEnum)
	if len(operationEnum) != len(inputs.Registry.Operations) {
		t.Fatalf("MCP operation count = %d", len(operationEnum))
	}
	for index, operation := range inputs.Registry.Operations {
		if operationEnum[index] != operation.Name {
			t.Fatalf("MCP operation %d = %q, want %q", index, operationEnum[index], operation.Name)
		}
	}

	var parity struct {
		RegistryDigest string `json:"registry_digest"`
		Operations     []struct {
			Name         string   `json:"name"`
			CLIPath      []string `json:"cli_path"`
			MCPTool      string   `json:"mcp_tool"`
			MCPOperation string   `json:"mcp_operation"`
		} `json:"operations"`
	}
	if err := json.Unmarshal(byPath["tests/generated/parity.json"], &parity); err != nil {
		t.Fatal(err)
	}
	if parity.RegistryDigest != inputs.RegistryDigest || len(parity.Operations) != len(inputs.Registry.Operations) {
		t.Fatalf("unexpected parity descriptor: %+v", parity)
	}
	for index, operation := range parity.Operations {
		if operation.Name != inputs.Registry.Operations[index].Name || operation.MCPTool != "ehjint" || operation.MCPOperation != operation.Name || len(operation.CLIPath) == 0 {
			t.Fatalf("parity mismatch at %d: %+v", index, operation)
		}
	}
}
