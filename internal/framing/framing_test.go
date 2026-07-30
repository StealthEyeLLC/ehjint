package framing

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"testing"
)

type frameRecord struct {
	Name string `json:"name"`
}

type oneByteWriter struct{ bytes.Buffer }

func (writer *oneByteWriter) Write(data []byte) (int, error) {
	if len(data) > 1 {
		data = data[:1]
	}
	return writer.Buffer.Write(data)
}

func TestRoundTripAndShortWrites(t *testing.T) {
	var wire oneByteWriter
	if err := Write(&wire, frameRecord{Name: "exact"}, DefaultMaxFrame); err != nil {
		t.Fatal(err)
	}
	var decoded frameRecord
	if err := Read(bytes.NewReader(wire.Bytes()), &decoded, DefaultMaxFrame); err != nil {
		t.Fatal(err)
	}
	if decoded.Name != "exact" {
		t.Fatalf("decoded = %+v", decoded)
	}
}

func TestRejectsEmptyOversizedPartialUnknownAndTrailing(t *testing.T) {
	makeWire := func(payload []byte) []byte {
		wire := make([]byte, PrefixSize+len(payload))
		binary.BigEndian.PutUint32(wire[:PrefixSize], uint32(len(payload)))
		copy(wire[PrefixSize:], payload)
		return wire
	}
	var record frameRecord
	if err := Read(bytes.NewReader([]byte{0, 0, 0, 0}), &record, 64); !errors.Is(err, ErrEmptyFrame) {
		t.Fatalf("empty frame error = %v", err)
	}
	if err := Read(bytes.NewReader([]byte{0, 0, 1, 0}), &record, 64); !errors.Is(err, ErrFrameTooLarge) {
		t.Fatalf("oversized frame error = %v", err)
	}
	if err := Read(bytes.NewReader(makeWire([]byte(`{"name":"x"}`))[:7]), &record, 64); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("partial frame error = %v", err)
	}
	if err := Read(bytes.NewReader(makeWire([]byte(`{"name":"x","extra":true}`))), &record, 128); err == nil {
		t.Fatal("unknown field accepted")
	}
	if err := Read(bytes.NewReader(makeWire([]byte(`{"name":"x"}{"name":"y"}`))), &record, 128); err == nil {
		t.Fatal("concatenated JSON accepted")
	}
	if err := Read(bytes.NewReader(makeWire([]byte(`{"name":`))), &record, 128); err == nil {
		t.Fatal("partial JSON accepted")
	}
}

func TestWriteRejectsOversizedAndInvalidValues(t *testing.T) {
	var wire bytes.Buffer
	if err := Write(&wire, frameRecord{Name: "too large"}, 4); !errors.Is(err, ErrFrameTooLarge) {
		t.Fatalf("oversized write error = %v", err)
	}
	if err := Write(&wire, func() {}, DefaultMaxFrame); err == nil {
		t.Fatal("unencodable value accepted")
	}
}
