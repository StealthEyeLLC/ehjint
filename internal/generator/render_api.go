package generator

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/StealthEyeLLC/ehjint/internal/registry"
)

func renderOperationCatalog(inputs Inputs) ([]byte, error) {
	type catalog struct {
		Generated      string               `json:"_generated"`
		SchemaVersion  int                  `json:"schema_version"`
		RegistryDigest string               `json:"registry_digest"`
		Operations     []registry.Operation `json:"operations"`
	}
	return prettyJSON(catalog{
		Generated:      generatedHeader,
		SchemaVersion:  1,
		RegistryDigest: inputs.RegistryDigest,
		Operations:     inputs.Registry.Operations,
	})
}

func renderCLI(inputs Inputs) ([]byte, error) {
	type command struct {
		Operation    string                 `json:"operation"`
		Version      int                    `json:"version"`
		Summary      string                 `json:"summary"`
		Path         []string               `json:"path"`
		Arguments    []registry.CLIArgument `json:"arguments"`
		JSONFlag     bool                   `json:"json_flag"`
		Availability string                 `json:"availability"`
	}
	type cli struct {
		Generated      string    `json:"_generated"`
		SchemaVersion  int       `json:"schema_version"`
		RegistryDigest string    `json:"registry_digest"`
		Binary         string    `json:"binary"`
		Aliases        []string  `json:"aliases"`
		Commands       []command `json:"commands"`
	}
	commands := make([]command, 0, len(inputs.Registry.Operations))
	for _, operation := range inputs.Registry.Operations {
		commands = append(commands, command{
			Operation:    operation.Name,
			Version:      operation.Version,
			Summary:      operation.Summary,
			Path:         operation.CLI.Path,
			Arguments:    operation.CLI.Arguments,
			JSONFlag:     operation.CLI.JSONFlag,
			Availability: operation.Availability,
		})
	}
	return prettyJSON(cli{
		Generated:      generatedHeader,
		SchemaVersion:  1,
		RegistryDigest: inputs.RegistryDigest,
		Binary:         "ehjint",
		Aliases:        []string{"ej"},
		Commands:       commands,
	})
}

func renderMCP(inputs Inputs) ([]byte, error) {
	names := make([]string, 0, len(inputs.Registry.Operations))
	branches := make([]any, 0, len(inputs.Registry.Operations))
	outputs := make([]any, 0, len(inputs.Registry.Operations))
	for _, operation := range inputs.Registry.Operations {
		names = append(names, operation.Name)
		inputSchema, err := rawObject(operation.InputSchema)
		if err != nil {
			return nil, err
		}
		outputSchema, err := rawObject(operation.OutputSchema)
		if err != nil {
			return nil, err
		}
		branches = append(branches, map[string]any{
			"if": map[string]any{
				"properties": map[string]any{"operation": map[string]any{"const": operation.Name}},
				"required":   []string{"operation"},
			},
			"then": map[string]any{
				"properties": map[string]any{"input": inputSchema},
			},
		})
		outputs = append(outputs, outputSchema)
	}
	sort.Strings(names)
	inputSchema := map[string]any{
		"$schema":              "https://json-schema.org/draft/2020-12/schema",
		"type":                 "object",
		"additionalProperties": false,
		"required":             []string{"operation", "input"},
		"properties": map[string]any{
			"operation": map[string]any{"type": "string", "enum": names},
			"input":     map[string]any{"type": "object"},
		},
		"allOf": branches,
	}
	outputSchema := map[string]any{
		"$schema": "https://json-schema.org/draft/2020-12/schema",
		"oneOf":   outputs,
	}
	type tool struct {
		Name         string         `json:"name"`
		Description  string         `json:"description"`
		InputSchema  map[string]any `json:"input_schema"`
		OutputSchema map[string]any `json:"output_schema"`
	}
	type document struct {
		Generated      string `json:"_generated"`
		SchemaVersion  int    `json:"schema_version"`
		RegistryDigest string `json:"registry_digest"`
		Tools          []tool `json:"tools"`
	}
	return prettyJSON(document{
		Generated:      generatedHeader,
		SchemaVersion:  1,
		RegistryDigest: inputs.RegistryDigest,
		Tools: []tool{{
			Name:         "ehjint",
			Description:  "Dispatch one canonical EHJINT operation. The operation registry is the sole semantic authority.",
			InputSchema:  inputSchema,
			OutputSchema: outputSchema,
		}},
	})
}

func renderCompatibility(inputs Inputs) ([]byte, error) {
	type document struct {
		Generated      string `json:"_generated"`
		SchemaVersion  int    `json:"schema_version"`
		RegistryDigest string `json:"registry_digest"`
		Contracts      []any  `json:"contracts"`
	}
	contracts := make([]any, 0, len(inputs.Compatibility.Contracts))
	for _, contract := range inputs.Compatibility.Contracts {
		contracts = append(contracts, map[string]any{"name": contract.Name, "version": contract.Version})
	}
	return prettyJSON(document{
		Generated:      generatedHeader,
		SchemaVersion:  1,
		RegistryDigest: inputs.RegistryDigest,
		Contracts:      contracts,
	})
}

func renderProviderContracts(inputs Inputs) ([]byte, error) {
	type document struct {
		Generated      string `json:"_generated"`
		SchemaVersion  int    `json:"schema_version"`
		RegistryDigest string `json:"registry_digest"`
		Contracts      []any  `json:"contracts"`
	}
	contracts := make([]any, 0, len(inputs.ProviderContracts.Contracts))
	for _, contract := range inputs.ProviderContracts.Contracts {
		contracts = append(contracts, map[string]any{
			"kind":                 contract.Kind,
			"version":              contract.Version,
			"capabilities":         contract.Capabilities,
			"lifecycle":            contract.Lifecycle,
			"ownership":            contract.Ownership,
			"failure_truth":        contract.FailureTruth,
			"implementation_state": contract.ImplementationState,
		})
	}
	return prettyJSON(document{
		Generated:      generatedHeader,
		SchemaVersion:  1,
		RegistryDigest: inputs.RegistryDigest,
		Contracts:      contracts,
	})
}

func renderRegistryDigest(inputs Inputs) ([]byte, error) {
	return []byte("# " + generatedHeader + "\nsha256:" + inputs.RegistryDigest + "\n"), nil
}

func renderParity(inputs Inputs) ([]byte, error) {
	type operation struct {
		Name               string   `json:"name"`
		Version            int      `json:"version"`
		CLIPath            []string `json:"cli_path"`
		MCPTool            string   `json:"mcp_tool"`
		MCPOperation       string   `json:"mcp_operation"`
		InputSchemaSHA256  string   `json:"input_schema_sha256"`
		OutputSchemaSHA256 string   `json:"output_schema_sha256"`
	}
	type parity struct {
		Generated      string      `json:"_generated"`
		SchemaVersion  int         `json:"schema_version"`
		RegistryDigest string      `json:"registry_digest"`
		Operations     []operation `json:"operations"`
	}
	operations := make([]operation, 0, len(inputs.Registry.Operations))
	for _, item := range inputs.Registry.Operations {
		operations = append(operations, operation{
			Name:               item.Name,
			Version:            item.Version,
			CLIPath:            item.CLI.Path,
			MCPTool:            item.MCP.Tool,
			MCPOperation:       item.MCP.Operation,
			InputSchemaSHA256:  digest(item.InputSchema),
			OutputSchemaSHA256: digest(item.OutputSchema),
		})
	}
	return prettyJSON(parity{
		Generated:      generatedHeader,
		SchemaVersion:  1,
		RegistryDigest: inputs.RegistryDigest,
		Operations:     operations,
	})
}

func renderOperationSchema(operation registry.Operation, direction string) ([]byte, error) {
	var raw json.RawMessage
	switch direction {
	case "input":
		raw = operation.InputSchema
	case "output":
		raw = operation.OutputSchema
	default:
		return nil, fmt.Errorf("unknown schema direction %q", direction)
	}
	schema, err := rawObject(raw)
	if err != nil {
		return nil, err
	}
	schema["$comment"] = generatedHeader
	schema["$id"] = fmt.Sprintf("urn:ehjint:operation:%s:%s:v%d", operation.Name, direction, operation.Version)
	schema["title"] = fmt.Sprintf("EHJINT %s %s schema v%d", operation.Name, direction, operation.Version)
	return prettyJSON(schema)
}

func rawObject(raw json.RawMessage) (map[string]any, error) {
	var object map[string]any
	if err := json.Unmarshal(raw, &object); err != nil {
		return nil, err
	}
	if object == nil {
		return nil, fmt.Errorf("schema is not an object")
	}
	return object, nil
}

func markdownEscape(value string) string {
	return strings.ReplaceAll(value, "|", "\\|")
}
