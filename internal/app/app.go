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
	"time"

	"github.com/StealthEyeLLC/ehjint/internal/contracts"
	"github.com/StealthEyeLLC/ehjint/internal/controller"
	"github.com/StealthEyeLLC/ehjint/internal/controlproto"
	"github.com/StealthEyeLLC/ehjint/internal/guestagent"
	"github.com/StealthEyeLLC/ehjint/internal/layout"
	"github.com/StealthEyeLLC/ehjint/internal/machine"
	"github.com/StealthEyeLLC/ehjint/internal/registry"
	"github.com/StealthEyeLLC/ehjint/internal/vmm"
)

type invocationOptions struct {
	JSON           bool
	Root           string
	IdempotencyKey string
}

// Run executes one EHJINT invocation and returns its stable process exit status.
func Run(argv0 string, args []string, stdout, stderr io.Writer) int {
	if len(args) > 0 && args[0] == "internal" {
		return runInternal(args, stderr)
	}
	invocation := filepath.Base(argv0)
	options, operands, publicError := parseArguments(args)
	if publicError != nil {
		return writePublicError(stderr, options.JSON, *publicError)
	}
	if len(operands) == 0 {
		return writePublicError(stderr, options.JSON, contracts.ErrorEnvelope{
			SchemaVersion: 1, Code: contracts.CodeFailedPrecondition,
			Message: "choose a registry-declared EHJINT operation", Operation: "system.dispatch", Retryable: false,
		})
	}

	catalog := registry.Compiled()
	operation, input, err := catalog.ResolveCLI(operands)
	if err != nil {
		code := contracts.CodeInvalidArgument
		if err.Error() == "unknown command" {
			code = contracts.CodeUnknownOperation
		}
		return writePublicError(stderr, options.JSON, contracts.ErrorEnvelope{
			SchemaVersion: 1, Code: code, Message: err.Error(), Operation: "system.dispatch", Retryable: false,
		})
	}

	var result any
	if operation.Availability == "active" {
		result, publicError = dispatchController(invocation, operation, input, options, stdout, stderr)
	} else {
		result, publicError = dispatch(catalog, invocation, registry.OperationID(operation.Name), input)
	}
	if publicError != nil {
		return writePublicError(stderr, options.JSON, *publicError)
	}
	if err := writeResult(stdout, options.JSON, registry.OperationID(operation.Name), result); err != nil {
		return writePublicError(stderr, options.JSON, contracts.ErrorEnvelope{
			SchemaVersion: 1, Code: contracts.CodeInternal, Message: "failed to encode command result",
			Operation: operation.Name, Retryable: false, Details: map[string]any{"cause": err.Error()},
		})
	}
	if diagnostic, ok := result.(DiagnosticResult); ok && !diagnostic.Healthy {
		return contracts.ExitStatus(contracts.CodeFailedPrecondition)
	}
	return 0
}

func dispatchController(invocation string, operation registry.Operation, input map[string]any, options invocationOptions, stdout, stderr io.Writer) (any, *contracts.ErrorEnvelope) {
	if operation.Idempotency == "required" && options.IdempotencyKey == "" {
		return nil, operationError(contracts.CodeInvalidArgument, operation.Name, "--idempotency-key is required")
	}
	inputBytes, err := json.Marshal(input)
	if err != nil {
		return nil, operationError(contracts.CodeInternal, operation.Name, "failed to encode controller input")
	}
	requestID, err := controller.NewRequestID()
	if err != nil {
		return nil, operationError(contracts.CodeInternal, operation.Name, "failed to create request identity")
	}
	paths := layout.Canonical()
	if options.Root != "/" {
		paths = layout.UnderRoot(options.Root)
	}
	request := controlproto.Request{
		ProtocolVersion: controlproto.Version, RequestID: requestID, Operation: operation.Name,
		OperationVersion: operation.Version, IdempotencyKey: options.IdempotencyKey,
		Invocation: invocation, TimeoutMillis: int64((30 * time.Minute) / time.Millisecond), Input: inputBytes,
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	defer cancel()
	response, err := controller.Call(ctx, paths.ControllerSocket, request, controller.Streams{Stdout: stdout, Stderr: stderr})
	if err != nil {
		var public *controller.PublicError
		if errors.As(err, &public) {
			return nil, &public.Envelope
		}
		return nil, operationError(contracts.CodeUnavailable, operation.Name, boundedAppError(err.Error()))
	}
	if response.ExitStatus != nil {
		return map[string]any{"operation_id": response.OperationID, "exit_status": *response.ExitStatus}, nil
	}
	if len(response.Payload) == 0 {
		return nil, operationError(contracts.CodeInternal, operation.Name, "controller returned no result")
	}
	var result any
	decoder := json.NewDecoder(strings.NewReader(string(response.Payload)))
	decoder.UseNumber()
	if err := decoder.Decode(&result); err != nil {
		return nil, operationError(contracts.CodeInternal, operation.Name, "controller returned invalid result")
	}
	return result, nil
}

func boundedAppError(message string) string {
	if len(message) > 1024 {
		return message[:1024]
	}
	return message
}

func runInternal(args []string, stderr io.Writer) int {
	if len(args) != 4 || args[0] != "internal" {
		fmt.Fprintln(stderr, "invalid internal EHJINT invocation")
		return contracts.ExitStatus(contracts.CodeInvalidArgument)
	}
	switch args[1] {
	case "controller":
		if args[2] != "--config" || !filepath.IsAbs(args[3]) || filepath.Clean(args[3]) != args[3] {
			fmt.Fprintln(stderr, "internal controller invocation requires: internal controller --config <canonical-absolute-path>")
			return contracts.ExitStatus(contracts.CodeInvalidArgument)
		}
		ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
		defer stop()
		if err := machine.ServeController(ctx, args[3]); err != nil {
			if errors.Is(err, context.Canceled) {
				return 0
			}
			fmt.Fprintf(stderr, "internal controller failed: %v\n", err)
			return contracts.ExitStatus(contracts.CodeInternal)
		}
		return 0
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

func parseArguments(args []string) (invocationOptions, []string, *contracts.ErrorEnvelope) {
	options := invocationOptions{Root: "/"}
	operands := make([]string, 0, len(args))
	for _, argument := range args {
		switch {
		case argument == "--json":
			if options.JSON {
				return options, nil, argumentError("duplicate --json flag")
			}
			options.JSON = true
		case strings.HasPrefix(argument, "--root="):
			value := strings.TrimPrefix(argument, "--root=")
			if options.Root != "/" || !filepath.IsAbs(value) || filepath.Clean(value) != value || value == "/" {
				return options, nil, argumentError("--root requires one non-root canonical absolute path")
			}
			options.Root = value
		case strings.HasPrefix(argument, "--idempotency-key="):
			value := strings.TrimPrefix(argument, "--idempotency-key=")
			if options.IdempotencyKey != "" || value == "" || len(value) > 256 || strings.ContainsRune(value, '\x00') {
				return options, nil, argumentError("--idempotency-key requires one bounded nonempty value")
			}
			options.IdempotencyKey = value
		case strings.HasPrefix(argument, "-"):
			return options, nil, argumentError("unknown flag " + argument)
		default:
			operands = append(operands, argument)
		}
	}
	return options, operands, nil
}

func argumentError(message string) *contracts.ErrorEnvelope {
	return &contracts.ErrorEnvelope{SchemaVersion: 1, Code: contracts.CodeInvalidArgument, Message: message, Operation: "system.dispatch", Retryable: false}
}

func writePublicError(writer io.Writer, jsonOutput bool, envelope contracts.ErrorEnvelope) int {
	if validationError := contracts.ValidateErrorEnvelope(envelope); validationError != nil {
		envelope = contracts.ErrorEnvelope{SchemaVersion: 1, Code: contracts.CodeInternal, Message: "invalid public error envelope", Operation: "system.dispatch", Retryable: false}
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
