// Copyright 2026 The ThunderID Authors
// SPDX-License-Identifier: Apache-2.0

package audit

import "errors"

var (
	errMissingTarget = errors.New("audit target has no type")
	errMissingAction = errors.New("audit action is empty")
	errUnknownResult = errors.New("audit outcome is not succeeded, denied or failed")
	errMissingReason = errors.New("a denied or failed audit outcome needs a reason")
	errInvalidReason = errors.New("audit outcome reason is not a stable lowercase code")
	errNilBus        = errors.New("the management audit middleware needs an event bus")
	errNilSink       = errors.New("audit sink is nil")
)
