package app

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/StealthEyeLLC/ehjint/internal/registry"
)

func writeResult(writer io.Writer, jsonOutput bool, operation registry.OperationID, result any) error {
	if jsonOutput {
		encoder := json.NewEncoder(writer)
		encoder.SetEscapeHTML(false)
		return encoder.Encode(result)
	}
	switch operation {
	case registry.OperationSystemVersion:
		value := result.(VersionResult)
		_, err := fmt.Fprintf(writer, "%s %s (%s) registry=%s invocation=%s\n", value.Product, value.ProductVersion, value.GoVersion, value.RegistryDigest, value.Invocation)
		return err
	case registry.OperationRegistryList:
		value := result.(RegistryListResult)
		if _, err := fmt.Fprintf(writer, "registry=%s operations=%d\n", value.RegistryDigest, len(value.Operations)); err != nil {
			return err
		}
		for _, operation := range value.Operations {
			if _, err := fmt.Fprintf(writer, "%s v%d [%s/%s] %s\n", operation.Name, operation.Version, operation.Classification, operation.Availability, operation.Summary); err != nil {
				return err
			}
		}
		return nil
	case registry.OperationRegistryDescribe:
		value := result.(RegistryDescribeResult)
		operation := value.Operation
		_, err := fmt.Fprintf(writer, "%s v%d\nsummary: %s\nclassification: %s\ncli: ehjint %s\nmcp: %s\nidempotency: %s\nstreaming: %s\nerrors: %s\n",
			operation.Name,
			operation.Version,
			operation.Summary,
			operation.Classification,
			strings.Join(operation.CLIPath, " "),
			operation.MCPTool,
			operation.Idempotency,
			operation.Streaming,
			strings.Join(operation.ErrorCodes, ","),
		)
		return err
	case registry.OperationSystemDiagnose:
		value := result.(DiagnosticResult)
		_, err := fmt.Fprintf(writer, "healthy=%t foundation_only=%t later_runtime_activated=%t registry=%t generated=%t compatibility=%t dependencies=%t providers=%t platform=%s/%s invocation=%s\n",
			value.Healthy,
			value.FoundationOnly,
			value.LaterRuntimeActivated,
			value.RegistrySchemaValid && value.RegistryDigestAgreement,
			value.GeneratedArtifactAgreement,
			value.CompatibilityVersionsAvailable,
			value.DependencyLockReadable,
			value.ProviderContractsValid,
			value.Platform,
			value.Architecture,
			value.Invocation,
		)
		return err
	default:
		return fmt.Errorf("no human renderer for operation %q", operation)
	}
}
