// Copyright 2026 The ThunderID Authors
// SPDX-License-Identifier: Apache-2.0

// Package stdoutsink is the default audit sink. It writes each audit event to standard output as one
// JSON line that starts with the configured type marker, whatever the diagnostic log level or format.
package stdoutsink

import (
	"os"

	"github.com/thunder-id/thunderid/internal/system/config"
	"github.com/thunder-id/thunderid/internal/system/eventbus/audit"
)

// Initialize creates the stdout sink with the type marker in cfg. An invalid marker key or value is
// refused, so the server does not start with lines a filter cannot find.
func Initialize(cfg config.LogTypeConfig) (audit.Sink, error) {
	sink, err := newStdoutSink(os.Stdout, cfg)
	if err != nil {
		return nil, err
	}
	return sink, nil
}
