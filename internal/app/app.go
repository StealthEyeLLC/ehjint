// Package app owns EHJINT invocation and registry-derived command dispatch.
package app

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/StealthEyeLLC/ehjint/internal/contracts"
	"github.com/StealthEyeLLC/ehjint/internal/guestagent"
	"github.com/StealthEyeLLC/ehjint/internal/registry"
	"github.com/StealthEyeLLC/ehjint/internal/vmm"
)

// Run executes one EHJINT invocation and returns its stable process exit status.
func Run(argv0 string, args []string, stdout, stderr io.Writer) int {
	if len(args) > 0 && args[0] == "internal" {
		return runInternal(args, stderr)
	}
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

func runInternal(args []string, stderr io.Writer) int {
	if len(args) != 4 || args[0] != "internal" {
		fmt.Fprintln(stderr, "invalid internal EHJINT invocation")
		return contracts.ExitStatus(contracts.CodeInvalidArgument)
	}
	switch args[1] {
	case "guest-agent":
		if args[2] != "--config" || !filepath.IsAbs(args[3]) || filepath.Clean(args[3]) != args[3] {
			fmt.Fprintln(stderr, "internal guest-agent invocation requires: internal guest-agent --config <canonical-absolute-path>")
			return contracts.ExitStatus(contracts.CodeInvalidArgument)
		}
		ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
		defer stop()
		if err := guestagent.Run(ctx, args[3]); err != nil {
			if errors.Is(err, context.Canceled) {
				return 0
			}
			fmt.Fprintf(stderr, "internal guest-agent failed: %v\n", err)
			return contracts.ExitStatus(contracts.CodeInternal)
		}
		return 0
	case "vmm-launch":
		if args[2] != "--spec-fd" {
			fmt.Fprintln(stderr, "internal VMM launcher invocation requires: internal vmm-launch --spec-fd <descriptor>")
			return contracts.ExitStatus(contracts.CodeInvalidArgument)
		}
		descriptor, err := vmm.ParseSpecFD(args[3])
		if err != nil {
			fmt.Fprintf(stderr, "internal VMM launcher invocation is invalid: %v\n", err)
			return contracts.ExitStatus(contracts.CodeInvalidArgument)
		}
		if err := vmm.RunLauncher(descriptor); err != nil {
			fmt.Fprintf(stderr, "internal VMM launcher failed: %v\n", err)
			return contracts.ExitStatus(contracts.CodeInternal)
		}
		return 0
	default:
		fmt.Fprintln(stderr, "unknown internal EHJINT mode")
		return contracts.ExitStatus(contracts.CodeInvalidArgument)
	}
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
