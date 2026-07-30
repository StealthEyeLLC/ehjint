package app

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

type topLevelSchema struct {
	AdditionalProperties *bool                      `json:"additionalProperties"`
	Required             []string                   `json:"required"`
	Properties           map[string]json.RawMessage `json:"properties"`
}

func appRepositoryRoot(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(file), "..", ".."))
}

func loadTopLevelSchema(t *testing.T, relative string) topLevelSchema {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(appRepositoryRoot(t), filepath.FromSlash(relative)))
	if err != nil {
		t.Fatal(err)
	}
	var schema topLevelSchema
	if err := json.Unmarshal(data, &schema); err != nil {
		t.Fatal(err)
	}
	if schema.AdditionalProperties == nil || *schema.AdditionalProperties || schema.Properties == nil {
		t.Fatalf("schema %s is not a strict object", relative)
	}
	return schema
}

func assertJSONMatchesTopLevelSchema(t *testing.T, data []byte, relative string) {
	t.Helper()
	var value map[string]any
	if err := json.Unmarshal(data, &value); err != nil {
		t.Fatalf("decode result JSON: %v", err)
	}
	schema := loadTopLevelSchema(t, relative)
	for _, required := range schema.Required {
		if _, ok := value[required]; !ok {
			t.Fatalf("%s result misses required property %q: %s", relative, required, data)
		}
	}
	for name, resultValue := range value {
		rawProperty, ok := schema.Properties[name]
		if !ok {
			t.Fatalf("%s result has undeclared property %q: %s", relative, name, data)
		}
		var property struct {
			Type string `json:"type"`
		}
		if err := json.Unmarshal(rawProperty, &property); err != nil {
			t.Fatal(err)
		}
		if property.Type != "" && !matchesJSONType(resultValue, property.Type) {
			t.Fatalf("%s property %q has wrong JSON type %T, want %s", relative, name, resultValue, property.Type)
		}
	}
}

func matchesJSONType(value any, kind string) bool {
	switch kind {
	case "string":
		_, ok := value.(string)
		return ok
	case "boolean":
		_, ok := value.(bool)
		return ok
	case "object":
		_, ok := value.(map[string]any)
		return ok
	case "array":
		_, ok := value.([]any)
		return ok
	case "integer":
		number, ok := value.(float64)
		return ok && number == float64(int64(number))
	case "number":
		_, ok := value.(float64)
		return ok
	default:
		return true
	}
}

func TestFoundationCLIResultsMatchGeneratedSchemas(t *testing.T) {
	tests := []struct {
		name      string
		arguments []string
		operation string
	}{
		{"version", []string{"version"}, "system-version"},
		{"doctor", []string{"doctor"}, "system-diagnose"},
		{"registry list", []string{"registry", "list"}, "registry-list"},
		{"registry describe", []string{"registry", "describe", "system.version"}, "registry-describe"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			code, stdout, stderr := runJSON(t, "ehjint", test.arguments...)
			if code != 0 {
				t.Fatalf("code=%d stderr=%s", code, stderr)
			}
			assertJSONMatchesTopLevelSchema(t, stdout, "api/schemas/operations/"+test.operation+".output.schema.json")
		})
	}
}

func TestPublicErrorMatchesGeneratedEnvelopeSchema(t *testing.T) {
	code, stdout, stderr := runJSON(t, "ehjint", "machine", "start")
	if code == 0 || len(stdout) != 0 || !strings.Contains(string(stderr), "unknown_operation") {
		t.Fatalf("code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	assertJSONMatchesTopLevelSchema(t, stderr, "api/schemas/contracts/error-envelope.schema.json")
}
