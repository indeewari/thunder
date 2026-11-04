// Copyright 2026 The ThunderID Authors
// SPDX-License-Identifier: Apache-2.0

package eventbus

import (
	"regexp"
	"time"
)

const (
	// DeliveryBestEffort drops an event when a subscriber cannot take it.
	DeliveryBestEffort DeliveryMode = "best_effort"

	defaultQueueSize       = 1024
	defaultDeliveryTimeout = 5 * time.Second
	defaultShutdownTimeout = 5 * time.Second
	// shutdownGrace is how long Stop waits for the workers after canceling the deliveries in flight.
	shutdownGrace = 250 * time.Millisecond
	// logInterval is the least time between two log lines of one kind for one subscriber.
	logInterval        = 30 * time.Second
	maxEventNameLength = 64
	// invalidEventName stands in for a name that fails the grammar, so a caller's text never reaches the log.
	invalidEventName = "invalid"
)

// eventNamePattern is the grammar of an event name: two to four lowercase segments joined by dots.
var eventNamePattern = regexp.MustCompile(`^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*){1,3}$`)
