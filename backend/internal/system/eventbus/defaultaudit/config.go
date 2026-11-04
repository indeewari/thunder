// Copyright 2026 The ThunderID Authors
// SPDX-License-Identifier: Apache-2.0

package defaultaudit

import (
	"time"

	"github.com/thunder-id/thunderid/internal/system/config"
)

// Config configures the audit event bus of one binary.
type Config struct {
	// Source names the binary in every audit line, for example server or control_plane.
	Source string
	// ShutdownTimeout bounds how long stopping the bus lets queued events drain.
	ShutdownTimeout time.Duration
	// Audit is the audit section of the deployment configuration.
	Audit config.AuditConfig
	// LogType is the type marker that leads every audit line.
	LogType config.LogTypeConfig
}
