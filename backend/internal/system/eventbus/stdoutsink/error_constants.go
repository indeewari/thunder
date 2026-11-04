// Copyright 2026 The ThunderID Authors
// SPDX-License-Identifier: Apache-2.0

package stdoutsink

import "errors"

var (
	errInvalidTypeKey = errors.New(
		"log.type.key must be letters, digits and underscores, and must not name a field of the audit line")
	errInvalidTypeValue = errors.New("log.type.audit must be non-empty and contain no whitespace")
	errLineTooLong      = errors.New("audit line does not fit the line size limit")
)
