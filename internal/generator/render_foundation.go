package generator

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strconv"
)

func renderFoundationGo(inputs Inputs) ([]byte, error) {
	compatibility, err := json.Marshal(inputs.Compatibility)
	if err != nil {
		return nil, err
	}
	providers, err := json.Marshal(inputs.ProviderContracts)
	if err != nil {
		return nil, err
	}
	dependencies, err := json.Marshal(inputs.Dependencies)
	if err != nil {
		return nil, err
	}
	toolchain, err := json.Marshal(inputs.Toolchain)
	if err != nil {
		return nil, err
	}
	var output bytes.Buffer
	fmt.Fprintf(&output, "// %s\n\n", generatedHeader)
	output.WriteString("// Package foundation contains validated, immutable Mission 1 contract inputs.\n")
	output.WriteString("package foundation\n\n")
	output.WriteString("const (\n")
	fmt.Fprintf(&output, "\tRegistryDigest = %s\n", strconv.Quote(inputs.RegistryDigest))
	fmt.Fprintf(&output, "\tCompatibilityJSON = %s\n", strconv.Quote(string(compatibility)))
	fmt.Fprintf(&output, "\tProviderContractsJSON = %s\n", strconv.Quote(string(providers)))
	fmt.Fprintf(&output, "\tDependencyLockJSON = %s\n", strconv.Quote(string(dependencies)))
	fmt.Fprintf(&output, "\tToolchainLockJSON = %s\n", strconv.Quote(string(toolchain)))
	output.WriteString(")\n")
	return formattedGo(output.Bytes())
}
