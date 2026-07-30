// Package framing provides EHJINT's bounded, length-prefixed strict JSON wire
// primitive. It is shared by the local controller socket and guest vsock
// protocol so neither transport invents implicit EOF or unbounded decoding.
package framing

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

const (
	PrefixSize      = 4
	DefaultMaxFrame = 1024 * 1024
)

var (
	ErrEmptyFrame    = errors.New("empty frame")
	ErrFrameTooLarge = errors.New("frame exceeds configured bound")
	ErrShortWrite    = errors.New("short frame write")
)

// Read decodes exactly one big-endian length-prefixed strict JSON frame.
func Read(reader io.Reader, target any, maximum uint32) error {
	if reader == nil || target == nil {
		return fmt.Errorf("reader and target are required")
	}
	if maximum == 0 {
		return fmt.Errorf("maximum frame size must be positive")
	}
	var prefix [PrefixSize]byte
	if _, err := io.ReadFull(reader, prefix[:]); err != nil {
		return fmt.Errorf("read frame length: %w", err)
	}
	length := binary.BigEndian.Uint32(prefix[:])
	if length == 0 {
		return ErrEmptyFrame
	}
	if length > maximum {
		return fmt.Errorf("%w: %d > %d", ErrFrameTooLarge, length, maximum)
	}
	payload := make([]byte, length)
	if _, err := io.ReadFull(reader, payload); err != nil {
		return fmt.Errorf("read complete frame payload: %w", err)
	}
	decoder := json.NewDecoder(bytesReader(payload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return fmt.Errorf("decode strict frame: %w", err)
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		if err == nil {
			return fmt.Errorf("decode strict frame: second JSON value")
		}
		return fmt.Errorf("decode strict frame trailing data: %w", err)
	}
	return nil
}

// Write encodes exactly one compact JSON value with a bounded length prefix.
func Write(writer io.Writer, value any, maximum uint32) error {
	if writer == nil || value == nil {
		return fmt.Errorf("writer and value are required")
	}
	if maximum == 0 {
		return fmt.Errorf("maximum frame size must be positive")
	}
	payload, err := json.Marshal(value)
	if err != nil {
		return fmt.Errorf("encode frame: %w", err)
	}
	if len(payload) == 0 {
		return ErrEmptyFrame
	}
	if uint64(len(payload)) > uint64(maximum) {
		return fmt.Errorf("%w: %d > %d", ErrFrameTooLarge, len(payload), maximum)
	}
	var prefix [PrefixSize]byte
	binary.BigEndian.PutUint32(prefix[:], uint32(len(payload)))
	if err := writeAll(writer, prefix[:]); err != nil {
		return fmt.Errorf("write frame length: %w", err)
	}
	if err := writeAll(writer, payload); err != nil {
		return fmt.Errorf("write complete frame payload: %w", err)
	}
	return nil
}

func writeAll(writer io.Writer, data []byte) error {
	for len(data) > 0 {
		written, err := writer.Write(data)
		if err != nil {
			return err
		}
		if written <= 0 || written > len(data) {
			return ErrShortWrite
		}
		data = data[written:]
	}
	return nil
}

// byteSliceReader is deliberately tiny and avoids accepting buffered trailing
// bytes outside the declared frame.
type byteSliceReader struct {
	data []byte
	off  int
}

func bytesReader(data []byte) *byteSliceReader { return &byteSliceReader{data: data} }

func (reader *byteSliceReader) Read(destination []byte) (int, error) {
	if reader.off >= len(reader.data) {
		return 0, io.EOF
	}
	count := copy(destination, reader.data[reader.off:])
	reader.off += count
	return count, nil
}
