package generator

import "fmt"

const (
	operationNamePattern = `^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)+$`
	sha256PatternSchema  = `^[0-9a-f]{64}$`
	gitObjectPattern     = `^[0-9a-f]{40}$`
)

func contractSchemas(inputs Inputs) map[string][]byte {
	schemas := map[string]map[string]any{
		"api/schemas/contracts/cancellation-request.schema.json":      cancellationRequestSchema(),
		"api/schemas/contracts/compatibility.schema.json":             compatibilitySchema(inputs),
		"api/schemas/contracts/dependency-lock.schema.json":           dependencyLockSchema(),
		"api/schemas/contracts/error-envelope.schema.json":            errorEnvelopeSchema(),
		"api/schemas/contracts/idempotency-record.schema.json":        idempotencyRecordSchema(),
		"api/schemas/contracts/machine-manifest.schema.json":          machineManifestSchema(),
		"api/schemas/contracts/operation-registry-source.schema.json": operationRegistrySourceSchema(),
		"api/schemas/contracts/provider-contracts.schema.json":        providerContractsSchema(),
		"api/schemas/contracts/release-manifest.schema.json":          releaseManifestSchema(inputs),
		"api/schemas/contracts/result-envelope.schema.json":           resultEnvelopeSchema(),
		"api/schemas/contracts/toolchain-lock.schema.json":            toolchainLockSchema(),
	}
	result := make(map[string][]byte, len(schemas))
	for path, schema := range schemas {
		schema["$schema"] = "https://json-schema.org/draft/2020-12/schema"
		schema["$comment"] = generatedHeader
		data, err := prettyJSON(schema)
		if err != nil {
			panic(fmt.Sprintf("render known JSON schema %s: %v", path, err))
		}
		result[path] = data
	}
	return result
}

func cancellationRequestSchema() map[string]any {
	return objectContract(
		"urn:ehjint:contract:cancellation-request:v1",
		"EHJINT cancellation request v1",
		[]string{"requested"},
		map[string]any{"requested": map[string]any{"type": "boolean"}},
	)
}

func compatibilitySchema(inputs Inputs) map[string]any {
	names := make([]string, 0, len(inputs.Compatibility.Contracts))
	for _, contract := range inputs.Compatibility.Contracts {
		names = append(names, contract.Name)
	}
	contract := objectValue(
		[]string{"name", "version"},
		map[string]any{
			"name":    map[string]any{"type": "string", "enum": names},
			"version": map[string]any{"type": "integer", "const": 1},
		},
	)
	return objectContract(
		"urn:ehjint:contract:compatibility:v1",
		"EHJINT compatibility contract v1",
		[]string{"schema_version", "contracts"},
		map[string]any{
			"schema_version": map[string]any{"type": "integer", "const": 1},
			"contracts": map[string]any{
				"type":        "array",
				"minItems":    len(names),
				"maxItems":    len(names),
				"uniqueItems": true,
				"items":       contract,
			},
		},
	)
}

func errorEnvelopeSchema() map[string]any {
	return objectContract(
		"urn:ehjint:contract:error-envelope:v1",
		"EHJINT error envelope v1",
		[]string{"schema_version", "code", "message", "operation", "retryable"},
		map[string]any{
			"schema_version": map[string]any{"type": "integer", "const": 1},
			"code": map[string]any{
				"type": "string",
				"enum": []string{
					"invalid_argument", "unknown_operation", "unsupported_version", "schema_mismatch",
					"conflict", "idempotency_conflict", "not_found", "permission_denied", "failed_precondition",
					"unavailable", "timeout", "cancelled", "internal",
				},
			},
			"message":      map[string]any{"type": "string", "minLength": 1, "maxLength": 1024},
			"operation":    map[string]any{"type": "string", "pattern": operationNamePattern},
			"operation_id": identifierSchema("op_"),
			"retryable":    map[string]any{"type": "boolean"},
			"details":      map[string]any{"type": "object"},
		},
	)
}

func resultEnvelopeSchema() map[string]any {
	schema := objectContract(
		"urn:ehjint:contract:result-envelope:v1",
		"EHJINT result envelope v1",
		[]string{"schema_version", "operation", "operation_version", "state"},
		map[string]any{
			"schema_version":    map[string]any{"type": "integer", "const": 1},
			"operation":         map[string]any{"type": "string", "pattern": operationNamePattern},
			"operation_version": map[string]any{"type": "integer", "const": 1},
			"operation_id":      identifierSchema("op_"),
			"state": map[string]any{
				"type": "string",
				"enum": []string{"accepted", "running", "succeeded", "failed", "cancelled"},
			},
			"result": true,
			"error":  map[string]any{"$ref": "error-envelope.schema.json"},
		},
	)
	schema["oneOf"] = []any{
		map[string]any{
			"properties": map[string]any{"state": map[string]any{"const": "succeeded"}},
			"required":   []string{"result"},
			"not":        map[string]any{"required": []string{"error"}},
		},
		map[string]any{
			"properties": map[string]any{"state": map[string]any{"enum": []string{"failed", "cancelled"}}},
			"required":   []string{"error"},
			"not":        map[string]any{"required": []string{"result"}},
		},
		map[string]any{
			"properties": map[string]any{"state": map[string]any{"enum": []string{"accepted", "running"}}},
			"not":        map[string]any{"anyOf": []any{map[string]any{"required": []string{"result"}}, map[string]any{"required": []string{"error"}}}},
		},
	}
	return schema
}

func idempotencyRecordSchema() map[string]any {
	return objectContract(
		"urn:ehjint:contract:idempotency-record:v1",
		"EHJINT idempotency record v1",
		[]string{"key", "request_digest", "operation_id"},
		map[string]any{
			"key":            map[string]any{"type": "string", "pattern": `^[A-Za-z0-9._:-]{8,128}$`},
			"request_digest": map[string]any{"type": "string", "pattern": sha256PatternSchema},
			"operation_id":   identifierSchema("op_"),
		},
	)
}

func dependencyLockSchema() map[string]any {
	dependency := objectValue(
		[]string{"name", "purpose", "version", "source", "digest", "license", "license_source", "scope", "distributed", "target_platforms", "verification"},
		map[string]any{
			"name":             map[string]any{"type": "string", "minLength": 1},
			"purpose":          map[string]any{"type": "string", "minLength": 1},
			"version":          map[string]any{"type": "string", "minLength": 1},
			"source":           map[string]any{"type": "string", "pattern": `^https://`},
			"digest":           map[string]any{"type": "string", "pattern": `^(sha256:[0-9a-f]{64}|git:[0-9a-f]{40})$`},
			"license":          map[string]any{"type": "string", "minLength": 1},
			"license_source":   map[string]any{"type": "string", "pattern": `^https://`},
			"scope":            map[string]any{"type": "string", "enum": []string{"build", "test", "build_test", "runtime", "ci"}},
			"distributed":      map[string]any{"type": "boolean"},
			"target_platforms": stringArray(1),
			"verification":     map[string]any{"type": "string", "minLength": 1},
		},
	)
	return objectContract(
		"urn:ehjint:contract:dependency-lock:v1",
		"EHJINT dependency lock v1",
		[]string{"schema_version", "dependencies"},
		map[string]any{
			"schema_version": map[string]any{"type": "integer", "const": 1},
			"dependencies":   map[string]any{"type": "array", "minItems": 1, "uniqueItems": true, "items": dependency},
		},
	)
}

func toolchainLockSchema() map[string]any {
	goToolchain := objectValue(
		[]string{"version", "target", "archive", "url", "sha256", "license", "license_source"},
		map[string]any{
			"version":        map[string]any{"type": "string", "pattern": `^go[0-9]+\.[0-9]+\.[0-9]+$`},
			"target":         map[string]any{"type": "string", "const": "linux/amd64"},
			"archive":        map[string]any{"type": "string", "minLength": 1},
			"url":            map[string]any{"type": "string", "pattern": `^https://go\.dev/dl/`},
			"sha256":         map[string]any{"type": "string", "pattern": sha256PatternSchema},
			"license":        map[string]any{"type": "string", "const": "BSD-3-Clause"},
			"license_source": map[string]any{"type": "string", "pattern": `^https://go\.dev/`},
		},
	)
	return objectContract(
		"urn:ehjint:contract:toolchain-lock:v1",
		"EHJINT toolchain lock v1",
		[]string{"schema_version", "go"},
		map[string]any{
			"schema_version": map[string]any{"type": "integer", "const": 1},
			"go":             goToolchain,
		},
	)
}

func providerContractsSchema() map[string]any {
	provider := objectValue(
		[]string{"kind", "version", "capabilities", "lifecycle", "ownership", "failure_truth", "implementation_state"},
		map[string]any{
			"kind": map[string]any{
				"type": "string",
				"enum": []string{"browser_pack", "device", "guest_image", "network", "protocol_edge", "storage", "vmm", "workspace"},
			},
			"version":              map[string]any{"type": "integer", "const": 1},
			"capabilities":         namedStringArray(1),
			"lifecycle":            namedStringArray(1),
			"ownership":            map[string]any{"type": "string", "const": "owned_resources_only"},
			"failure_truth":        map[string]any{"type": "string", "const": "explicit"},
			"implementation_state": map[string]any{"type": "string", "const": "contract_only"},
		},
	)
	return objectContract(
		"urn:ehjint:contract:provider-contracts:v1",
		"EHJINT provider contracts v1",
		[]string{"schema_version", "contracts"},
		map[string]any{
			"schema_version": map[string]any{"type": "integer", "const": 1},
			"contracts":      map[string]any{"type": "array", "minItems": 8, "maxItems": 8, "uniqueItems": true, "items": provider},
		},
	)
}

func machineManifestSchema() map[string]any {
	component := objectValue(
		[]string{"provider", "version", "digest"},
		map[string]any{
			"provider": map[string]any{"type": "string", "pattern": `^[a-z][a-z0-9_-]{0,63}$`},
			"version":  map[string]any{"type": "string", "minLength": 1},
			"digest":   map[string]any{"type": "string", "pattern": sha256PatternSchema},
		},
	)
	cpu := objectValue(
		[]string{"vcpus", "mode"},
		map[string]any{
			"vcpus": map[string]any{"type": "integer", "minimum": 1, "maximum": 1024},
			"mode":  map[string]any{"type": "string", "enum": []string{"generic", "host"}},
		},
	)
	memory := objectValue(
		[]string{"bytes", "huge_pages"},
		map[string]any{
			"bytes":      map[string]any{"type": "integer", "minimum": 134217728, "multipleOf": 1048576},
			"huge_pages": map[string]any{"type": "boolean"},
		},
	)
	disk := objectValue(
		[]string{"id", "role", "format", "base_digest", "overlay_id"},
		map[string]any{
			"id":          namedString(),
			"role":        map[string]any{"type": "string", "enum": []string{"root", "data"}},
			"format":      map[string]any{"type": "string", "enum": []string{"raw", "qcow2"}},
			"base_digest": map[string]any{"type": "string", "pattern": sha256PatternSchema},
			"overlay_id":  namedString(),
		},
	)
	interfaceBinding := objectValue(
		[]string{"name", "model"},
		map[string]any{
			"name":  namedString(),
			"model": map[string]any{"type": "string", "enum": []string{"virtio", "none"}},
		},
	)
	network := objectValue(
		[]string{"mode", "interfaces"},
		map[string]any{
			"mode":       map[string]any{"type": "string", "enum": []string{"automatic_nat", "none", "custom"}},
			"interfaces": map[string]any{"type": "array", "uniqueItems": true, "items": interfaceBinding},
		},
	)
	device := objectValue(
		[]string{"kind", "host_reference", "guest_reference", "required"},
		map[string]any{
			"kind":            namedString(),
			"host_reference":  map[string]any{"type": "string", "minLength": 1},
			"guest_reference": map[string]any{"type": "string", "minLength": 1},
			"required":        map[string]any{"type": "boolean"},
		},
	)
	workspace := objectValue(
		[]string{"mode", "references"},
		map[string]any{
			"mode":       map[string]any{"type": "string", "enum": []string{"direct", "fork", "contained"}},
			"references": stringArray(0),
		},
	)
	lineage := objectValue(
		[]string{"parent_snapshot_id", "generation"},
		map[string]any{
			"parent_snapshot_id": map[string]any{"type": "string", "pattern": `^(|snap_[a-z2-7]{26})$`},
			"generation":         map[string]any{"type": "integer", "minimum": 0},
		},
	)
	return objectContract(
		"urn:ehjint:contract:machine-manifest:v1",
		"EHJINT machine manifest v1",
		[]string{
			"schema_version", "machine_id", "name", "architecture", "vmm", "firmware", "guest_image",
			"guest_agent_version", "cpu", "memory", "disks", "network", "devices", "capability_packs",
			"workspace", "snapshot_lineage", "required_host_capabilities", "creating_release_id",
		},
		map[string]any{
			"schema_version":             map[string]any{"type": "integer", "const": 1},
			"machine_id":                 identifierSchema("mach_"),
			"name":                       map[string]any{"type": "string", "pattern": `^[a-z][a-z0-9-]{0,62}$`},
			"architecture":               map[string]any{"type": "string", "enum": []string{"x86_64", "aarch64"}},
			"vmm":                        component,
			"firmware":                   component,
			"guest_image":                component,
			"guest_agent_version":        map[string]any{"type": "string", "minLength": 1},
			"cpu":                        cpu,
			"memory":                     memory,
			"disks":                      map[string]any{"type": "array", "minItems": 1, "uniqueItems": true, "items": disk},
			"network":                    network,
			"devices":                    map[string]any{"type": "array", "uniqueItems": true, "items": device},
			"capability_packs":           map[string]any{"type": "array", "uniqueItems": true, "items": identifierSchema("pack_")},
			"workspace":                  workspace,
			"snapshot_lineage":           lineage,
			"required_host_capabilities": namedStringArray(0),
			"creating_release_id":        identifierSchema("rel_"),
		},
	)
}

func releaseManifestSchema(inputs Inputs) map[string]any {
	compatibilityProperties := make(map[string]any, len(inputs.Compatibility.Contracts))
	compatibilityRequired := make([]string, 0, len(inputs.Compatibility.Contracts))
	for _, contract := range inputs.Compatibility.Contracts {
		compatibilityProperties[contract.Name] = map[string]any{"type": "integer", "const": contract.Version}
		compatibilityRequired = append(compatibilityRequired, contract.Name)
	}
	buildTarget := objectValue(
		[]string{"os", "arch"},
		map[string]any{
			"os":   map[string]any{"type": "string", "const": "linux"},
			"arch": map[string]any{"type": "string", "enum": []string{"amd64", "arm64"}},
		},
	)
	goToolchain := objectValue(
		[]string{"version", "archive_sha256"},
		map[string]any{
			"version":        map[string]any{"type": "string", "minLength": 1},
			"archive_sha256": map[string]any{"type": "string", "pattern": sha256PatternSchema},
		},
	)
	component := objectValue(
		[]string{"name", "version", "digest"},
		map[string]any{
			"name":    namedString(),
			"version": map[string]any{"type": "string", "minLength": 1},
			"digest":  map[string]any{"type": "string", "pattern": sha256PatternSchema},
		},
	)
	compatibility := map[string]any{
		"type":                 "object",
		"additionalProperties": false,
		"required":             compatibilityRequired,
		"properties":           compatibilityProperties,
	}
	provenance := objectValue(
		[]string{"builder_kind", "source_date_epoch", "reproducible"},
		map[string]any{
			"builder_kind":      map[string]any{"type": "string", "const": "local_reproducible"},
			"source_date_epoch": map[string]any{"type": "integer", "minimum": 1},
			"reproducible":      map[string]any{"type": "boolean", "const": true},
		},
	)
	return objectContract(
		"urn:ehjint:contract:release-manifest:v1",
		"EHJINT release manifest v1",
		[]string{
			"schema_version", "release_id", "product_version", "source_commit", "source_tree", "build_mode",
			"target", "go_toolchain", "registry_digest", "binary_digest", "components", "compatibility",
			"dependency_lock_digest", "guest_compatibility", "vmm_compatibility", "provenance",
		},
		map[string]any{
			"schema_version":         map[string]any{"type": "integer", "const": 1},
			"release_id":             identifierSchema("rel_"),
			"product_version":        map[string]any{"type": "string", "pattern": `^[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?$`},
			"source_commit":          map[string]any{"type": "string", "pattern": gitObjectPattern},
			"source_tree":            map[string]any{"type": "string", "pattern": gitObjectPattern},
			"build_mode":             map[string]any{"type": "string", "enum": []string{"development", "fast", "sovereign"}},
			"target":                 buildTarget,
			"go_toolchain":           goToolchain,
			"registry_digest":        map[string]any{"type": "string", "pattern": sha256PatternSchema},
			"binary_digest":          map[string]any{"type": "string", "pattern": sha256PatternSchema},
			"components":             map[string]any{"type": "array", "uniqueItems": true, "items": component},
			"compatibility":          compatibility,
			"dependency_lock_digest": map[string]any{"type": "string", "pattern": sha256PatternSchema},
			"guest_compatibility":    stringArray(1),
			"vmm_compatibility":      stringArray(1),
			"provenance":             provenance,
		},
	)
}

func operationRegistrySourceSchema() map[string]any {
	cliArgument := objectValue(
		[]string{"name", "required"},
		map[string]any{
			"name":     map[string]any{"type": "string", "pattern": `^[a-z][a-z0-9-]*$`},
			"required": map[string]any{"type": "boolean"},
		},
	)
	cli := objectValue(
		[]string{"path", "arguments", "json_flag"},
		map[string]any{
			"path":      map[string]any{"type": "array", "minItems": 1, "items": map[string]any{"type": "string", "pattern": `^[a-z][a-z0-9-]*$`}},
			"arguments": map[string]any{"type": "array", "items": cliArgument},
			"json_flag": map[string]any{"type": "boolean", "const": true},
		},
	)
	mcp := objectValue(
		[]string{"tool", "operation"},
		map[string]any{
			"tool":      map[string]any{"type": "string", "const": "ehjint"},
			"operation": map[string]any{"type": "string", "pattern": operationNamePattern},
		},
	)
	deprecation := objectValue(
		[]string{"since_version", "replacement"},
		map[string]any{
			"since_version": map[string]any{"type": "integer", "minimum": 1},
			"replacement":   map[string]any{"type": "string", "pattern": operationNamePattern},
		},
	)
	operation := objectValue(
		[]string{
			"name", "version", "summary", "classification", "input_schema", "output_schema", "unknown_fields",
			"idempotency", "streaming", "result_mode", "cancellation", "required_machine_state", "error_codes",
			"cli", "mcp", "availability", "deprecation",
		},
		map[string]any{
			"name":                   map[string]any{"type": "string", "pattern": operationNamePattern},
			"version":                map[string]any{"type": "integer", "const": 1},
			"summary":                map[string]any{"type": "string", "minLength": 1},
			"classification":         map[string]any{"type": "string", "enum": []string{"read_only", "mutating"}},
			"input_schema":           map[string]any{"type": "object"},
			"output_schema":          map[string]any{"type": "object"},
			"unknown_fields":         map[string]any{"type": "string", "const": "reject"},
			"idempotency":            map[string]any{"type": "string", "enum": []string{"none", "optional", "required"}},
			"streaming":              map[string]any{"type": "string", "enum": []string{"none", "bounded", "resumable"}},
			"result_mode":            map[string]any{"type": "string", "enum": []string{"single", "stream"}},
			"cancellation":           map[string]any{"type": "string", "enum": []string{"not_applicable", "cooperative"}},
			"required_machine_state": map[string]any{"type": "string", "minLength": 1},
			"error_codes":            namedStringArray(1),
			"cli":                    cli,
			"mcp":                    mcp,
			"availability":           map[string]any{"type": "string", "enum": []string{"foundation", "active", "future"}},
			"deprecation":            map[string]any{"oneOf": []any{map[string]any{"type": "null"}, deprecation}},
		},
	)
	return objectContract(
		"urn:ehjint:contract:operation-registry-source:v1",
		"EHJINT operation registry source v1",
		[]string{"schema_version", "operations"},
		map[string]any{
			"schema_version": map[string]any{"type": "integer", "const": 1},
			"operations":     map[string]any{"type": "array", "minItems": 1, "uniqueItems": true, "items": operation},
		},
	)
}

func objectContract(id, title string, required []string, properties map[string]any) map[string]any {
	schema := objectValue(required, properties)
	schema["$id"] = id
	schema["title"] = title
	return schema
}

func objectValue(required []string, properties map[string]any) map[string]any {
	return map[string]any{
		"type":                 "object",
		"additionalProperties": false,
		"required":             required,
		"properties":           properties,
	}
}

func identifierSchema(prefix string) map[string]any {
	return map[string]any{"type": "string", "pattern": "^" + prefix + `[a-z2-7]{26}$`}
}

func namedString() map[string]any {
	return map[string]any{"type": "string", "pattern": `^[a-z][a-z0-9_-]{0,63}$`}
}

func stringArray(minimum int) map[string]any {
	return map[string]any{
		"type":        "array",
		"minItems":    minimum,
		"uniqueItems": true,
		"items":       map[string]any{"type": "string", "minLength": 1},
	}
}

func namedStringArray(minimum int) map[string]any {
	return map[string]any{
		"type":        "array",
		"minItems":    minimum,
		"uniqueItems": true,
		"items":       namedString(),
	}
}
