package contracts

import "fmt"

// OperationState is the frozen durable operation state vocabulary.
type OperationState string

const (
	StateAccepted  OperationState = "accepted"
	StateRunning   OperationState = "running"
	StateSucceeded OperationState = "succeeded"
	StateFailed    OperationState = "failed"
	StateCancelled OperationState = "cancelled"
)

var validStates = map[OperationState]bool{
	StateAccepted: true, StateRunning: true, StateSucceeded: true, StateFailed: true, StateCancelled: true,
}

// CancellationRequest represents durable cancellation intent without claiming completion.
type CancellationRequest struct {
	Requested bool `json:"requested"`
}

// ValidOperationState reports whether state belongs to the frozen vocabulary.
func ValidOperationState(state OperationState) bool { return validStates[state] }

// Terminal reports whether no later operation state is legal.
func (state OperationState) Terminal() bool {
	return state == StateSucceeded || state == StateFailed || state == StateCancelled
}

// ValidateTransition rejects reopening terminal operations and every undeclared transition.
func ValidateTransition(from, to OperationState) error {
	if !ValidOperationState(from) || !ValidOperationState(to) {
		return fmt.Errorf("invalid operation state transition %q -> %q", from, to)
	}
	if from == to {
		return nil
	}
	allowed := false
	switch from {
	case StateAccepted:
		allowed = to == StateRunning || to == StateFailed || to == StateCancelled
	case StateRunning:
		allowed = to == StateSucceeded || to == StateFailed || to == StateCancelled
	}
	if !allowed {
		return fmt.Errorf("forbidden operation state transition %q -> %q", from, to)
	}
	return nil
}
