package vsock

import (
	"strings"
	"testing"
	"time"
)

func TestAddr(t *testing.T) {
	address := Addr{CID: 7, Port: 19000}
	if address.Network() != "vsock" || address.String() != "vsock:7:19000" {
		t.Fatalf("unexpected address: %s %s", address.Network(), address.String())
	}
}

func TestListenRejectsZeroPort(t *testing.T) {
	if _, err := Listen(0); err == nil || !strings.Contains(err.Error(), "nonzero") {
		t.Fatalf("zero port result: %v", err)
	}
}

func TestExpiredDeadlineConvertsToPositiveTimeout(t *testing.T) {
	// This tests the only platform-independent part of deadline conversion by
	// ensuring the helper never panics on an expired time. Invalid fd must still
	// return a syscall error rather than accepting the deadline silently.
	if err := setTimeout(-1, 0, time.Now().Add(-time.Second)); err == nil {
		t.Fatal("invalid descriptor accepted")
	}
}
