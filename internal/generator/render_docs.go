package generator

import (
	"bytes"
	"fmt"
	"strings"

	"github.com/StealthEyeLLC/ehjint/internal/registry"
)

func renderOperationsDoc(inputs Inputs) ([]byte, error) {
	var output bytes.Buffer
	fmt.Fprintf(&output, "<!-- %s -->\n\n", generatedHeader)
	output.WriteString("# EHJINT operation catalog\n\n")
	fmt.Fprintf(&output, "Registry SHA-256: `%s`\n\n", inputs.RegistryDigest)
	output.WriteString("Every row below is derived from `registry/operations.json`. The semantic operation name is the authority shared by the CLI and MCP surfaces.\n\n")
	output.WriteString("| Operation | Version | Class | CLI | MCP tool | Idempotency | Streaming | Availability |\n")
	output.WriteString("|---|---:|---|---|---|---|---|---|\n")
	for _, operation := range inputs.Registry.Operations {
		fmt.Fprintf(&output, "| `%s` | %d | `%s` | `%s` | `%s` | `%s` | `%s` | `%s` |\n",
			markdownEscape(operation.Name),
			operation.Version,
			markdownEscape(operation.Classification),
			markdownEscape(cliSyntax(operation.CLI.Path, operation.CLI.Arguments)),
			markdownEscape(operation.MCP.Tool),
			markdownEscape(operation.Idempotency),
			markdownEscape(operation.Streaming),
			markdownEscape(operation.Availability),
		)
	}
	for _, operation := range inputs.Registry.Operations {
		fmt.Fprintf(&output, "\n## `%s`\n\n", operation.Name)
		fmt.Fprintf(&output, "%s\n\n", operation.Summary)
		fmt.Fprintf(&output, "- Version: `%d`\n", operation.Version)
		fmt.Fprintf(&output, "- Classification: `%s`\n", operation.Classification)
		fmt.Fprintf(&output, "- Unknown input fields: `%s`\n", operation.UnknownFields)
		fmt.Fprintf(&output, "- Required machine state: `%s`\n", operation.RequiredMachineState)
		fmt.Fprintf(&output, "- Cancellation: `%s`\n", operation.Cancellation)
		fmt.Fprintf(&output, "- Result mode: `%s`\n", operation.ResultMode)
		fmt.Fprintf(&output, "- CLI: `%s`\n", cliSyntax(operation.CLI.Path, operation.CLI.Arguments))
		fmt.Fprintf(&output, "- MCP: tool `%s`, operation `%s`\n", operation.MCP.Tool, operation.MCP.Operation)
		fmt.Fprintf(&output, "- Stable errors: `%s`\n", strings.Join(operation.ErrorCodes, "`, `"))
		if operation.Deprecation == nil {
			output.WriteString("- Deprecation: none\n")
		} else {
			fmt.Fprintf(&output, "- Deprecated since v%d; replacement `%s`\n", operation.Deprecation.SinceVersion, operation.Deprecation.Replacement)
		}
	}
	return ensureFinalNewline(output.Bytes()), nil
}

func renderContractsDoc(inputs Inputs) ([]byte, error) {
	var output bytes.Buffer
	fmt.Fprintf(&output, "<!-- %s -->\n\n", generatedHeader)
	output.WriteString("# EHJINT Mission 1 contracts\n\n")
	fmt.Fprintf(&output, "Registry SHA-256: `%s`\n\n", inputs.RegistryDigest)
	output.WriteString("## Compatibility versions\n\n")
	output.WriteString("| Contract | Version |\n|---|---:|\n")
	for _, contract := range inputs.Compatibility.Contracts {
		fmt.Fprintf(&output, "| `%s` | %d |\n", contract.Name, contract.Version)
	}
	output.WriteString("\n## Provider boundaries\n\n")
	output.WriteString("Provider entries define future data and lifecycle boundaries only. Mission 1 does not activate a VMM, guest, network, storage, workspace, device, browser, or protocol runtime.\n\n")
	output.WriteString("| Provider kind | Version | Ownership | Failure truth | State | Lifecycle |\n")
	output.WriteString("|---|---:|---|---|---|---|\n")
	for _, contract := range inputs.ProviderContracts.Contracts {
		fmt.Fprintf(&output, "| `%s` | %d | `%s` | `%s` | `%s` | `%s` |\n",
			contract.Kind,
			contract.Version,
			contract.Ownership,
			contract.FailureTruth,
			contract.ImplementationState,
			strings.Join(contract.Lifecycle, " → "),
		)
	}
	output.WriteString("\n## Locked dependencies\n\n")
	output.WriteString("| Name | Version | Scope | Digest | License | Distributed |\n")
	output.WriteString("|---|---|---|---|---|---|\n")
	for _, dependency := range inputs.Dependencies.Dependencies {
		fmt.Fprintf(&output, "| `%s` | `%s` | `%s` | `%s` | `%s` | `%t` |\n",
			dependency.Name,
			dependency.Version,
			dependency.Scope,
			dependency.Digest,
			dependency.License,
			dependency.Distributed,
		)
	}
	return ensureFinalNewline(output.Bytes()), nil
}

func cliSyntax(path []string, arguments []registry.CLIArgument) string {
	parts := append([]string{"ehjint"}, path...)
	for _, argument := range arguments {
		if argument.Required {
			parts = append(parts, "<"+argument.Name+">")
		} else {
			parts = append(parts, "["+argument.Name+"]")
		}
	}
	return strings.Join(parts, " ")
}
