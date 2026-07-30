// Package app owns EHJINT invocation and registry-derived command dispatch.
package app

import (
	"encoding/json"
	"fmt"
	"io"
	"path/filepath"
	"strings"

	"github.com/StealthEyeLLC/ehjint/internal/contracts"
	"github.com/StealthEyeLLC/ehjint/internal/registry"
)

// Run executes one EHJINT invocation and returns its stable process exit status.
func Run(argv0 string, args []string, stdout, stderr io.Writer) int {
	invocation := filepath.Base(argv0)
	jsonOutput, operands, publicError := parseArguments(args)
	if publicError != nil {
		return writePublicError(stderr, jsonOutput, *publicError)
	}
	if len(operands) == 0 {
		return writePublicError(stderr, jsonOutput, contracts.ErrorEnvelope{
			SchemaVersion: 1,
			Code:          contracts.CodeFailedPrecondition,
			Message:       "Mission 1 provides diagnostics only; choose version, doctor, registry list, or registry describe <operation>",
			Operation:     "system.dispatch",
			Retryable:     false,
		})
	}

	catalog := registry.Compiled()
	operation, input, err := catalog.ResolveCLI(operands)
	if err != nil {
		code := contracts.CodeInvalidArgument
		if err.Error() == "unknown command" {
			code = contracts.CodeUnknownOperation
		}
		return writePublicError(stderr, jsonOutput, contracts.ErrorEnvelope{
			SchemaVersion: 1,
			Code:          code,
			Message:       err.Error(),
			Operation:     "system.dispatch",
			Retryable:     false,
		})
	}

	result, publicError := dispatch(catalog, invocation, registry.OperationID(operation.Name), input)
	if publicError != nil {
		return writePublicError(stderr, jsonOutput, *publicError)
	}
	if err := writeResult(stdout, jsonOutput, registry.OperationID(operation.Name), result); err != nil {
		return writePublicError(stderr, jsonOutput, contracts.ErrorEnvelope{
			SchemaVersion: 1,
			Code:          contracts.CodeInternal,
			Message:       "failed to encode command result",
			Operation:     operation.Name,
			Retryable:     false,
			Details:       map[string]any{"cause": err.Error()},
		})
	}
	if diagnostic, ok := result.(DiagnosticResult); ok && !diagnostic.Healthy {
		return contracts.ExitStatus(contracts.CodeFailedPrecondition)
	}
	return 0
}

func parseArguments(args []string) (bool, []string, *contracts.ErrorEnvelope) {
	jsonOutput := false
	operands := make([]string, 0, len(args))
	for _, argument := range args {
		switch {
		case argument == "--json":
			if jsonOutput {
				return false, nil, argumentError("duplicate --json flag")
			}
			jsonOutput = true
		case strings.HasPrefix(argument, "-"):
			return jsonOutput, nil, argumentError("unknown flag " + argument)
		default:
			operands = append(operands, argument)
		}
	}
	return jsonOutput, operands, nil
}

func argumentError(message string) *contracts.ErrorEnvelope {
	return &contracts.ErrorEnvelope{
		SchemaVersion: 1,
		Code:          contracts.CodeInvalidArgument,
		Message:       message,
		Operation:     "system.dispatch",
		Retryable:     false,
	}
}

func writePublicError(writer io.Writer, jsonOutput bool, envelope contracts.ErrorEnvelope) int {
	if validationError := contracts.ValidateErrorEnvelope(envelope); validationError != nil {
		envelope = contracts.ErrorEnvelope{
			SchemaVersion: 1,
			Code:          contracts.CodeInternal,
			Message:       "invalid public error envelope",
			Operation:     "system.dispatch",
			Retryable:     false,
		}
	}
	if jsonOutput {
		encoder := json.NewEncoder(writer)
		encoder.SetEscapeHTML(false)
		if err := encoder.Encode(envelope); err != nil {
			fmt.Fprintln(writer, "internal: failed to encode public error")
		}
	} else {
		fmt.Fprintf(writer, "%s: %s: %s\n", envelope.Operation, envelope.Code, envelope.Message)
	}
	return contracts.ExitStatus(envelope.Code)
}
