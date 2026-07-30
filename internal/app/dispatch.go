package app

import (
	"runtime"
	"sort"

	"github.com/StealthEyeLLC/ehjint/internal/contracts"
	"github.com/StealthEyeLLC/ehjint/internal/foundation"
	"github.com/StealthEyeLLC/ehjint/internal/registry"
	"github.com/StealthEyeLLC/ehjint/internal/version"
)

// VersionResult is the exact system.version output contract.
type VersionResult struct {
	Product        string         `json:"product"`
	ProductVersion string         `json:"product_version"`
	GoVersion      string         `json:"go_version"`
	RegistryDigest string         `json:"registry_digest"`
	Compatibility  map[string]int `json:"compatibility"`
	Invocation     string         `json:"invocation"`
}

// OperationSummary is the bounded registry.list projection.
type OperationSummary struct {
	Name           string `json:"name"`
	Version        int    `json:"version"`
	Summary        string `json:"summary"`
	Classification string `json:"classification"`
	Availability   string `json:"availability"`
}

// RegistryListResult is the exact registry.list output contract.
type RegistryListResult struct {
	RegistryDigest string             `json:"registry_digest"`
	Operations     []OperationSummary `json:"operations"`
}

// OperationDescription is the bounded registry.describe projection.
type OperationDescription struct {
	Name                 string   `json:"name"`
	Version              int      `json:"version"`
	Summary              string   `json:"summary"`
	Classification       string   `json:"classification"`
	UnknownFields        string   `json:"unknown_fields"`
	Idempotency          string   `json:"idempotency"`
	Streaming            string   `json:"streaming"`
	ResultMode           string   `json:"result_mode"`
	Cancellation         string   `json:"cancellation"`
	RequiredMachineState string   `json:"required_machine_state"`
	ErrorCodes           []string `json:"error_codes"`
	CLIPath              []string `json:"cli_path"`
	MCPTool              string   `json:"mcp_tool"`
	Availability         string   `json:"availability"`
	Deprecated           bool     `json:"deprecated"`
}

// RegistryDescribeResult is the exact registry.describe output contract.
type RegistryDescribeResult struct {
	RegistryDigest string               `json:"registry_digest"`
	Operation      OperationDescription `json:"operation"`
}

// DiagnosticResult is the exact system.diagnose output contract.
type DiagnosticResult struct {
	Healthy                        bool   `json:"healthy"`
	ProductVersion                 string `json:"product_version"`
	GoVersion                      string `json:"go_version"`
	RegistrySchemaValid            bool   `json:"registry_schema_valid"`
	RegistryDigestAgreement        bool   `json:"registry_digest_agreement"`
	GeneratedArtifactAgreement     bool   `json:"generated_artifact_agreement"`
	CompatibilityVersionsAvailable bool   `json:"compatibility_versions_available"`
	DependencyLockReadable         bool   `json:"dependency_lock_readable"`
	ProviderContractsValid         bool   `json:"provider_contracts_valid"`
	Platform                       string `json:"platform"`
	Architecture                   string `json:"architecture"`
	Invocation                     string `json:"invocation"`
	Alias                          bool   `json:"alias"`
	FoundationOnly                 bool   `json:"foundation_only"`
	LaterRuntimeActivated          bool   `json:"later_runtime_activated"`
}

func dispatch(catalog registry.Catalog, invocation string, operation registry.OperationID, input map[string]any) (any, *contracts.ErrorEnvelope) {
	switch operation {
	case registry.OperationSystemVersion:
		return versionResult(catalog, invocation), nil
	case registry.OperationRegistryList:
		return registryListResult(catalog), nil
	case registry.OperationRegistryDescribe:
		name, ok := input["operation"].(string)
		if !ok || name == "" {
			return nil, operationError(contracts.CodeInvalidArgument, string(operation), "operation is required")
		}
		result, ok := registryDescribeResult(catalog, name)
		if !ok {
			return nil, operationError(contracts.CodeUnknownOperation, string(operation), "unknown operation "+name)
		}
		return result, nil
	case registry.OperationSystemDiagnose:
		return diagnosticResult(catalog, invocation), nil
	default:
		return nil, operationError(contracts.CodeUnknownOperation, "system.dispatch", "operation has no Mission 1 handler")
	}
}

func versionResult(catalog registry.Catalog, invocation string) VersionResult {
	info := version.Current()
	return VersionResult{
		Product:        info.Product,
		ProductVersion: info.ProductVersion,
		GoVersion:      info.GoVersion,
		RegistryDigest: catalog.Digest(),
		Compatibility:  version.CompatibilityVersions(),
		Invocation:     invocation,
	}
}

func registryListResult(catalog registry.Catalog) RegistryListResult {
	operations := catalog.List()
	result := make([]OperationSummary, 0, len(operations))
	for _, operation := range operations {
		result = append(result, OperationSummary{
			Name:           operation.Name,
			Version:        operation.Version,
			Summary:        operation.Summary,
			Classification: operation.Classification,
			Availability:   operation.Availability,
		})
	}
	return RegistryListResult{RegistryDigest: catalog.Digest(), Operations: result}
}

func registryDescribeResult(catalog registry.Catalog, name string) (RegistryDescribeResult, bool) {
	operation, ok := catalog.Describe(name)
	if !ok {
		return RegistryDescribeResult{}, false
	}
	return RegistryDescribeResult{
		RegistryDigest: catalog.Digest(),
		Operation: OperationDescription{
			Name:                 operation.Name,
			Version:              operation.Version,
			Summary:              operation.Summary,
			Classification:       operation.Classification,
			UnknownFields:        operation.UnknownFields,
			Idempotency:          operation.Idempotency,
			Streaming:            operation.Streaming,
			ResultMode:           operation.ResultMode,
			Cancellation:         operation.Cancellation,
			RequiredMachineState: operation.RequiredMachineState,
			ErrorCodes:           append([]string(nil), operation.ErrorCodes...),
			CLIPath:              append([]string(nil), operation.CLI.Path...),
			MCPTool:              operation.MCP.Tool,
			Availability:         operation.Availability,
			Deprecated:           operation.Deprecation != nil,
		},
	}, true
}

func diagnosticResult(catalog registry.Catalog, invocation string) DiagnosticResult {
	compatibility, compatibilityError := contracts.ParseCompatibility([]byte(foundation.CompatibilityJSON))
	dependencies, dependencyError := contracts.ParseDependencyLock([]byte(foundation.DependencyLockJSON))
	toolchain, toolchainError := contracts.ParseToolchainLock([]byte(foundation.ToolchainLockJSON))
	providerContracts, providerError := contracts.ParseProviderContracts([]byte(foundation.ProviderContractsJSON))

	compatibilityAvailable := compatibilityError == nil && equalCompatibility(compatibility.Map(), version.CompatibilityVersions())
	dependencyReadable := dependencyError == nil && toolchainError == nil && contracts.VerifyToolchainDependencyAgreement(toolchain, dependencies) == nil
	providersValid := providerError == nil && len(providerContracts.Contracts) == 8
	registrySchemaValid := catalog.SchemaVersion() == 1 && len(catalog.List()) > 0
	registryDigestAgreement := catalog.Digest() == registry.GeneratedRegistryDigest && catalog.Digest() == foundation.RegistryDigest
	generatedAgreement := registryDigestAgreement && version.RegistryDigest == foundation.RegistryDigest
	healthy := registrySchemaValid && registryDigestAgreement && generatedAgreement && compatibilityAvailable && dependencyReadable && providersValid

	return DiagnosticResult{
		Healthy:                        healthy,
		ProductVersion:                 version.ProductVersion,
		GoVersion:                      runtime.Version(),
		RegistrySchemaValid:            registrySchemaValid,
		RegistryDigestAgreement:        registryDigestAgreement,
		GeneratedArtifactAgreement:     generatedAgreement,
		CompatibilityVersionsAvailable: compatibilityAvailable,
		DependencyLockReadable:         dependencyReadable,
		ProviderContractsValid:         providersValid,
		Platform:                       runtime.GOOS,
		Architecture:                   runtime.GOARCH,
		Invocation:                     invocation,
		Alias:                          invocation == "ej",
		FoundationOnly:                 false,
		LaterRuntimeActivated:          true,
	}
}

func equalCompatibility(left, right map[string]int) bool {
	if len(left) != len(right) {
		return false
	}
	keys := make([]string, 0, len(left))
	for key := range left {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		if left[key] != right[key] {
			return false
		}
	}
	return true
}

func operationError(code contracts.ErrorCode, operation, message string) *contracts.ErrorEnvelope {
	if operation == "" {
		operation = "system.dispatch"
	}
	return &contracts.ErrorEnvelope{
		SchemaVersion: 1,
		Code:          code,
		Message:       message,
		Operation:     operation,
		Retryable:     false,
	}
}
