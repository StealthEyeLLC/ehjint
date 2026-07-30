package registry

import (
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// OperationID is the generated typed semantic operation identifier.
type OperationID string

// Catalog is the immutable in-process view of the canonical registry.
type Catalog struct {
	source Source
	digest string
	byName map[string]Operation
}

// NewCatalog constructs a validated immutable catalog.
func NewCatalog(source Source, digest string) Catalog {
	owned := Source{SchemaVersion: source.SchemaVersion, Operations: make([]Operation, 0, len(source.Operations))}
	byName := make(map[string]Operation, len(source.Operations))
	for _, operation := range source.Operations {
		cloned := cloneOperation(operation)
		owned.Operations = append(owned.Operations, cloned)
		byName[cloned.Name] = cloned
	}
	return Catalog{source: owned, digest: digest, byName: byName}
}

// Digest returns the registry content digest.
func (catalog Catalog) Digest() string { return catalog.digest }

// SchemaVersion returns the registry source schema version.
func (catalog Catalog) SchemaVersion() int { return catalog.source.SchemaVersion }

// List returns a detached lexical copy.
func (catalog Catalog) List() []Operation {
	operations := make([]Operation, 0, len(catalog.source.Operations))
	for _, operation := range catalog.source.Operations {
		operations = append(operations, cloneOperation(operation))
	}
	sort.Slice(operations, func(i, j int) bool { return operations[i].Name < operations[j].Name })
	return operations
}

// Describe returns one declared operation.
func (catalog Catalog) Describe(name string) (Operation, bool) {
	operation, ok := catalog.byName[name]
	if !ok {
		return Operation{}, false
	}
	return cloneOperation(operation), true
}

// ResolveCLI derives operation and strict positional input from registry metadata.
func (catalog Catalog) ResolveCLI(arguments []string) (Operation, map[string]any, error) {
	for _, operation := range catalog.source.Operations {
		if len(arguments) < len(operation.CLI.Path) {
			continue
		}
		matched := true
		for index, token := range operation.CLI.Path {
			if arguments[index] != token {
				matched = false
				break
			}
		}
		if !matched {
			continue
		}
		values := arguments[len(operation.CLI.Path):]
		required := 0
		for _, argument := range operation.CLI.Arguments {
			if argument.Required {
				required++
			}
		}
		if len(values) < required || len(values) > len(operation.CLI.Arguments) {
			return Operation{}, nil, fmt.Errorf("%s expects %d..%d positional arguments", strings.Join(operation.CLI.Path, " "), required, len(operation.CLI.Arguments))
		}
		input := make(map[string]any, len(values))
		propertyTypes, err := operationInputTypes(operation.InputSchema)
		if err != nil {
			return Operation{}, nil, fmt.Errorf("%s input schema: %w", operation.Name, err)
		}
		for index, value := range values {
			name := operation.CLI.Arguments[index].Name
			converted, err := convertCLIValue(name, value, propertyTypes[name])
			if err != nil {
				return Operation{}, nil, err
			}
			input[name] = converted
		}
		return cloneOperation(operation), input, nil
	}
	return Operation{}, nil, fmt.Errorf("unknown command")
}

func cloneOperation(operation Operation) Operation {
	cloned := operation
	cloned.InputSchema = append([]byte(nil), operation.InputSchema...)
	cloned.OutputSchema = append([]byte(nil), operation.OutputSchema...)
	cloned.ErrorCodes = append([]string(nil), operation.ErrorCodes...)
	cloned.CLI.Path = append([]string(nil), operation.CLI.Path...)
	cloned.CLI.Arguments = append([]CLIArgument(nil), operation.CLI.Arguments...)
	if operation.Deprecation != nil {
		deprecation := *operation.Deprecation
		cloned.Deprecation = &deprecation
	}
	return cloned
}

func operationInputTypes(raw json.RawMessage) (map[string]string, error) {
	var schema struct {
		Properties map[string]json.RawMessage `json:"properties"`
	}
	if err := json.Unmarshal(raw, &schema); err != nil {
		return nil, err
	}
	result := make(map[string]string, len(schema.Properties))
	for name, property := range schema.Properties {
		var typed struct {
			Type string `json:"type"`
		}
		if err := json.Unmarshal(property, &typed); err != nil {
			return nil, err
		}
		result[name] = typed.Type
	}
	return result, nil
}

func convertCLIValue(name, value, propertyType string) (any, error) {
	switch propertyType {
	case "", "string":
		return value, nil
	case "integer":
		parsed, err := strconv.ParseInt(value, 10, 64)
		if err != nil {
			return nil, fmt.Errorf("%s must be an integer", name)
		}
		return parsed, nil
	case "boolean":
		parsed, err := strconv.ParseBool(value)
		if err != nil {
			return nil, fmt.Errorf("%s must be a boolean", name)
		}
		return parsed, nil
	default:
		return nil, fmt.Errorf("%s cannot be supplied positionally for schema type %q", name, propertyType)
	}
}
