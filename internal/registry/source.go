// Package registry loads, validates, and dispatches the single canonical operation registry.
package registry

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/StealthEyeLLC/ehjint/internal/contracts"
)

var operationNamePattern = regexp.MustCompile(`^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)+$`)
var cliTokenPattern = regexp.MustCompile(`^[a-z][a-z0-9-]*$`)
var cliArgumentPattern = regexp.MustCompile(`^[a-z][a-z0-9_]*$`)

// Source is the strict human-authored registry source.
type Source struct {
	SchemaVersion int         `json:"schema_version"`
	Operations    []Operation `json:"operations"`
}

// Operation declares one public operation exactly once.
type Operation struct {
	Name                 string          `json:"name"`
	Version              int             `json:"version"`
	Summary              string          `json:"summary"`
	Classification       string          `json:"classification"`
	InputSchema          json.RawMessage `json:"input_schema"`
	OutputSchema         json.RawMessage `json:"output_schema"`
	UnknownFields        string          `json:"unknown_fields"`
	Idempotency          string          `json:"idempotency"`
	Streaming            string          `json:"streaming"`
	ResultMode           string          `json:"result_mode"`
	Cancellation         string          `json:"cancellation"`
	RequiredMachineState string          `json:"required_machine_state"`
	ErrorCodes           []string        `json:"error_codes"`
	CLI                  CLIMapping      `json:"cli"`
	MCP                  MCPMapping      `json:"mcp"`
	Availability         string          `json:"availability"`
	Deprecation          *Deprecation    `json:"deprecation"`
}

// CLIMapping is generated into the one multicall command surface.
type CLIMapping struct {
	Path      []string      `json:"path"`
	Arguments []CLIArgument `json:"arguments"`
	JSONFlag  bool          `json:"json_flag"`
}

// CLIArgument binds one positional CLI value to an input property.
type CLIArgument struct {
	Name     string `json:"name"`
	Required bool   `json:"required"`
}

// MCPMapping keeps protocol mapping derived from the same operation declaration.
type MCPMapping struct {
	Tool      string `json:"tool"`
	Operation string `json:"operation"`
}

// Deprecation is nil until a real compatible replacement exists.
type Deprecation struct {
	SinceVersion int    `json:"since_version"`
	Replacement  string `json:"replacement"`
}

// ParseSource rejects unknown fields, contradictions, duplicates, and unstable ordering inputs.
func ParseSource(data []byte) (Source, string, error) {
	var source Source
	if err := contracts.DecodeStrict(data, &source); err != nil {
		return Source{}, "", err
	}
	if source.SchemaVersion != 1 {
		return Source{}, "", fmt.Errorf("unsupported registry schema version %d", source.SchemaVersion)
	}
	if len(source.Operations) == 0 {
		return Source{}, "", fmt.Errorf("registry contains no operations")
	}
	seenNames := make(map[string]bool, len(source.Operations))
	seenCLI := make(map[string]bool, len(source.Operations))
	for index := range source.Operations {
		operation := &source.Operations[index]
		if err := normalizeOperation(operation); err != nil {
			return Source{}, "", fmt.Errorf("operation %d: %w", index, err)
		}
		if seenNames[operation.Name] {
			return Source{}, "", fmt.Errorf("duplicate operation name %q", operation.Name)
		}
		seenNames[operation.Name] = true
		cliKey := strings.Join(operation.CLI.Path, "\x00")
		if seenCLI[cliKey] {
			return Source{}, "", fmt.Errorf("duplicate CLI mapping %q", strings.Join(operation.CLI.Path, " "))
		}
		seenCLI[cliKey] = true
	}
	sort.Slice(source.Operations, func(i, j int) bool { return source.Operations[i].Name < source.Operations[j].Name })
	canonical, err := json.Marshal(source)
	if err != nil {
		return Source{}, "", fmt.Errorf("encode normalized registry: %w", err)
	}
	digest := sha256.Sum256(canonical)
	return source, hex.EncodeToString(digest[:]), nil
}

func normalizeOperation(operation *Operation) error {
	if !operationNamePattern.MatchString(operation.Name) {
		return fmt.Errorf("invalid semantic name %q", operation.Name)
	}
	if operation.Version != 1 {
		return fmt.Errorf("unsupported operation version %d for %q", operation.Version, operation.Name)
	}
	if operation.Summary == "" {
		return fmt.Errorf("missing summary for %q", operation.Name)
	}
	if operation.Classification != "read_only" && operation.Classification != "mutating" {
		return fmt.Errorf("invalid classification %q", operation.Classification)
	}
	if operation.UnknownFields != "reject" {
		return fmt.Errorf("operation %q must reject unknown fields", operation.Name)
	}
	switch operation.Idempotency {
	case "none", "optional", "required":
	default:
		return fmt.Errorf("invalid idempotency policy %q", operation.Idempotency)
	}
	if operation.Classification == "read_only" && operation.Idempotency != "none" {
		return fmt.Errorf("read-only operation %q cannot declare mutating idempotency", operation.Name)
	}
	if operation.Classification == "mutating" && operation.Idempotency == "none" {
		return fmt.Errorf("mutating operation %q must declare idempotency", operation.Name)
	}
	switch operation.Streaming {
	case "none", "bounded", "resumable":
	default:
		return fmt.Errorf("invalid streaming policy %q", operation.Streaming)
	}
	if (operation.Streaming == "none") != (operation.ResultMode == "single") {
		return fmt.Errorf("operation %q has contradictory streaming and result declarations", operation.Name)
	}
	if operation.ResultMode != "single" && operation.ResultMode != "stream" {
		return fmt.Errorf("invalid result mode %q", operation.ResultMode)
	}
	if operation.Cancellation != "not_applicable" && operation.Cancellation != "cooperative" {
		return fmt.Errorf("invalid cancellation policy %q", operation.Cancellation)
	}
	if operation.RequiredMachineState == "" {
		return fmt.Errorf("missing required machine state")
	}
	if len(operation.ErrorCodes) == 0 {
		return fmt.Errorf("operation %q must declare stable error codes", operation.Name)
	}
	seenCodes := make(map[string]bool, len(operation.ErrorCodes))
	for _, code := range operation.ErrorCodes {
		if !validErrorCode(code) || seenCodes[code] {
			return fmt.Errorf("operation %q has invalid or duplicate error code %q", operation.Name, code)
		}
		seenCodes[code] = true
	}
	sort.Strings(operation.ErrorCodes)
	if len(operation.CLI.Path) == 0 {
		return fmt.Errorf("operation %q has no CLI mapping", operation.Name)
	}
	for _, token := range operation.CLI.Path {
		if !cliTokenPattern.MatchString(token) {
			return fmt.Errorf("operation %q has invalid CLI token %q", operation.Name, token)
		}
	}
	seenArguments := make(map[string]bool, len(operation.CLI.Arguments))
	optionalSeen := false
	for _, argument := range operation.CLI.Arguments {
		if !cliArgumentPattern.MatchString(argument.Name) || seenArguments[argument.Name] {
			return fmt.Errorf("operation %q has invalid or duplicate CLI argument %q", operation.Name, argument.Name)
		}
		if optionalSeen && argument.Required {
			return fmt.Errorf("operation %q has required argument after optional argument", operation.Name)
		}
		if !argument.Required {
			optionalSeen = true
		}
		seenArguments[argument.Name] = true
	}
	if !operation.CLI.JSONFlag {
		return fmt.Errorf("operation %q must expose strict JSON output", operation.Name)
	}
	if operation.MCP.Tool != "ehjint" || operation.MCP.Operation != operation.Name {
		return fmt.Errorf("operation %q has divergent MCP mapping", operation.Name)
	}
	if operation.Availability != "foundation" && operation.Availability != "active" && operation.Availability != "future" {
		return fmt.Errorf("operation %q has invalid availability %q", operation.Name, operation.Availability)
	}
	if operation.Deprecation != nil {
		if operation.Deprecation.SinceVersion < 1 || !operationNamePattern.MatchString(operation.Deprecation.Replacement) {
			return fmt.Errorf("operation %q has invalid deprecation metadata", operation.Name)
		}
	}
	input, err := normalizeSchema(operation.InputSchema)
	if err != nil {
		return fmt.Errorf("operation %q input schema: %w", operation.Name, err)
	}
	if err := validateCLIInputMapping(operation.CLI.Arguments, input); err != nil {
		return fmt.Errorf("operation %q CLI input mapping: %w", operation.Name, err)
	}
	output, err := normalizeSchema(operation.OutputSchema)
	if err != nil {
		return fmt.Errorf("operation %q output schema: %w", operation.Name, err)
	}
	operation.InputSchema = input
	operation.OutputSchema = output
	return nil
}

func normalizeSchema(raw json.RawMessage) (json.RawMessage, error) {
	if len(raw) == 0 {
		return nil, fmt.Errorf("missing schema")
	}
	canonical, err := contracts.CanonicalJSON(raw)
	if err != nil {
		return nil, err
	}
	var schema map[string]any
	if err := json.Unmarshal(canonical, &schema); err != nil {
		return nil, err
	}
	if schema["type"] != "object" || schema["additionalProperties"] != false {
		return nil, fmt.Errorf("schema must be an object with additionalProperties=false")
	}
	if _, _, err := objectSchemaFields(canonical); err != nil {
		return nil, err
	}
	return json.RawMessage(canonical), nil
}

func objectSchemaFields(raw []byte) (map[string]json.RawMessage, map[string]bool, error) {
	var schema struct {
		Properties map[string]json.RawMessage `json:"properties"`
		Required   []string                   `json:"required"`
	}
	if err := json.Unmarshal(raw, &schema); err != nil {
		return nil, nil, fmt.Errorf("decode object schema fields: %w", err)
	}
	if schema.Properties == nil {
		return nil, nil, fmt.Errorf("object schema must declare properties")
	}
	required := make(map[string]bool, len(schema.Required))
	for _, name := range schema.Required {
		if name == "" || required[name] {
			return nil, nil, fmt.Errorf("object schema has an empty or duplicate required property %q", name)
		}
		if _, ok := schema.Properties[name]; !ok {
			return nil, nil, fmt.Errorf("required property %q is not declared", name)
		}
		required[name] = true
	}
	return schema.Properties, required, nil
}

func validateCLIInputMapping(arguments []CLIArgument, raw json.RawMessage) error {
	properties, required, err := objectSchemaFields(raw)
	if err != nil {
		return err
	}
	mapped := make(map[string]bool, len(arguments))
	for _, argument := range arguments {
		if _, ok := properties[argument.Name]; !ok {
			return fmt.Errorf("argument %q has no input schema property", argument.Name)
		}
		if required[argument.Name] != argument.Required {
			return fmt.Errorf("argument %q requiredness disagrees with input schema", argument.Name)
		}
		mapped[argument.Name] = true
	}
	for name := range properties {
		if !mapped[name] {
			return fmt.Errorf("input schema property %q has no CLI argument mapping", name)
		}
	}
	return nil
}

func validErrorCode(code string) bool {
	switch contracts.ErrorCode(code) {
	case contracts.CodeInvalidArgument, contracts.CodeUnknownOperation, contracts.CodeUnsupportedVersion,
		contracts.CodeSchemaMismatch, contracts.CodeConflict, contracts.CodeIdempotencyConflict,
		contracts.CodeNotFound, contracts.CodePermissionDenied, contracts.CodeFailedPrecondition, contracts.CodeUnavailable,
		contracts.CodeTimeout, contracts.CodeCancelled, contracts.CodeInternal:
		return true
	default:
		return false
	}
}
