// Copyright 2026 The ThunderID Authors
// SPDX-License-Identifier: Apache-2.0

package stdoutsink

import (
	"bytes"
	"context"
	"encoding/json"
	"io"

	"github.com/thunder-id/thunderid/internal/system/config"
	"github.com/thunder-id/thunderid/internal/system/eventbus"
	"github.com/thunder-id/thunderid/internal/system/eventbus/audit"
)

// stdoutSink writes each audit event as one line in a single Write call, so a concurrent writer to
// the same descriptor cannot split it while the line stays within the pipe atomic write size.
type stdoutSink struct {
	writer io.Writer
	// marker is the rendered type marker and the comma that follows it.
	marker []byte
}

// newStdoutSink creates a sink that writes to writer, with the marker in cfg rendered once.
func newStdoutSink(writer io.Writer, cfg config.LogTypeConfig) (*stdoutSink, error) {
	marker, err := renderMarker(cfg)
	if err != nil {
		return nil, err
	}
	return &stdoutSink{writer: writer, marker: marker}, nil
}

// Handle writes one audit line. A line that cannot be brought under the size limit is not written.
func (s *stdoutSink) Handle(_ context.Context, env eventbus.Envelope, payload audit.Payload) error {
	buf, err := s.render(newLine(env, payload))
	if err != nil {
		return err
	}
	_, err = s.writer.Write(buf)
	return err
}

// render encodes l as one line within maxLineBytes. A line over the limit loses its details, largest
// first, then part of its user agent, and finally has every free-form field capped.
func (s *stdoutSink) render(l line) ([]byte, error) {
	buf, err := s.encode(&l)
	for err == nil && len(buf) > maxLineBytes && len(l.Details) > 0 {
		delete(l.Details, largestDetail(l.Details))
		buf, err = s.encode(&l)
	}
	for err == nil && len(buf) > maxLineBytes && l.Client != nil && l.Client.UserAgent != "" {
		excess := len(buf) - maxLineBytes
		l.Client.UserAgent = truncateBytes(l.Client.UserAgent, len(l.Client.UserAgent)-excess)
		buf, err = s.encode(&l)
	}
	if err == nil && len(buf) > maxLineBytes {
		capFields(&l)
		buf, err = s.encode(&l)
	}
	if err != nil {
		return nil, err
	}
	if len(buf) > maxLineBytes {
		return nil, errLineTooLong
	}
	return buf, nil
}

// encode renders l as a newline-terminated JSON object with the marker as its first member.
func (s *stdoutSink) encode(l *line) ([]byte, error) {
	var body bytes.Buffer
	encoder := json.NewEncoder(&body)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(l); err != nil {
		return nil, err
	}
	encoded := body.Bytes()
	buf := make([]byte, 0, 1+len(s.marker)+len(encoded))
	buf = append(buf, '{')
	buf = append(buf, s.marker...)
	return append(buf, encoded[1:]...), nil
}
