package generator

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"unicode"

	"github.com/StealthEyeLLC/ehjint/internal/registry"
)

func renderRegistryGo(inputs Inputs) ([]byte, error) {
	canonicalRegistry, err := json.Marshal(inputs.Registry)
	if err != nil {
		return nil, err
	}
	var output bytes.Buffer
	fmt.Fprintf(&output, "// %s\n\n", generatedHeader)
	output.WriteString("package registry\n\n")
	output.WriteString("const (\n")
	for _, operation := range inputs.Registry.Operations {
		fmt.Fprintf(&output, "\tOperation%s OperationID = %s\n", goOperationName(operation.Name), strconv.Quote(operation.Name))
	}
	fmt.Fprintf(&output, "\tGeneratedRegistryDigest = %s\n", strconv.Quote(inputs.RegistryDigest))
	output.WriteString(")\n\n")
	fmt.Fprintf(&output, "const generatedRegistryJSON = %s\n\n", strconv.Quote(string(canonicalRegistry)))
	output.WriteString("var generatedCatalog = mustLoadGeneratedCatalog()\n\n")
	output.WriteString("func mustLoadGeneratedCatalog() Catalog {\n")
	output.WriteString("\tsource, digest, err := ParseSource([]byte(generatedRegistryJSON))\n")
	output.WriteString("\tif err != nil {\n")
	output.WriteString("\t\tpanic(\"invalid compiled operation registry: \" + err.Error())\n")
	output.WriteString("\t}\n")
	output.WriteString("\tif digest != GeneratedRegistryDigest {\n")
	output.WriteString("\t\tpanic(\"compiled operation registry digest mismatch\")\n")
	output.WriteString("\t}\n")
	output.WriteString("\treturn NewCatalog(source, digest)\n")
	output.WriteString("}\n\n")
	output.WriteString("// Compiled returns the immutable generated operation catalog.\n")
	output.WriteString("func Compiled() Catalog { return generatedCatalog }\n")
	return formattedGo(output.Bytes())
}

func renderVersionGo(inputs Inputs) ([]byte, error) {
	var output bytes.Buffer
	fmt.Fprintf(&output, "// %s\n\n", generatedHeader)
	output.WriteString("package version\n\n")
	fmt.Fprintf(&output, "const RegistryDigest = %s\n\n", strconv.Quote(inputs.RegistryDigest))
	output.WriteString("// CompatibilityVersions returns a detached copy of the frozen Mission 1 compatibility set.\n")
	output.WriteString("func CompatibilityVersions() map[string]int {\n")
	output.WriteString("\treturn map[string]int{\n")
	for _, contract := range inputs.Compatibility.Contracts {
		fmt.Fprintf(&output, "\t\t%s: %d,\n", strconv.Quote(contract.Name), contract.Version)
	}
	output.WriteString("\t}\n")
	output.WriteString("}\n")
	return formattedGo(output.Bytes())
}

func goOperationName(name string) string {
	var result strings.Builder
	upper := true
	for _, character := range name {
		if character == '.' || character == '_' || character == '-' {
			upper = true
			continue
		}
		if upper {
			result.WriteRune(unicode.ToUpper(character))
			upper = false
			continue
		}
		result.WriteRune(character)
	}
	return result.String()
}

func operationConstant(operation registry.Operation) string {
	return "Operation" + goOperationName(operation.Name)
}
