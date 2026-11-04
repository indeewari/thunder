// Copyright 2026 The ThunderID Authors
// SPDX-License-Identifier: Apache-2.0

package eventbus

import "errors"

var (
	errInvalidEventName       = errors.New("event name does not follow the dotted lowercase grammar")
	errNoPayload              = errors.New("event carries no payload")
	errNilPayload             = errors.New("payload is nil")
	errDuplicateCategory      = errors.New("event already carries a payload of this category")
	errNilEvent               = errors.New("event is nil")
	errBusClosed              = errors.New("event bus is shut down")
	errEmptySubscriberID      = errors.New("subscriber id is empty")
	errDuplicateSubscriberID  = errors.New("subscriber id is already registered")
	errNilHandler             = errors.New("subscriber handler is nil")
	errUnsupportedDelivery    = errors.New("unsupported delivery guarantee")
	errMissingPayload         = errors.New("event lacks a payload its catalog entry requires")
	errUnregisteredEvent      = errors.New("event name is not in the catalog")
	errEmptySource            = errors.New("event bus source is empty")
	errInvalidPayload         = errors.New("payload failed validation")
	errEventID                = errors.New("failed to generate an event id")
	errInstanceID             = errors.New("failed to resolve the instance id")
	errInvalidShutdownTimeout = errors.New("event bus shutdown timeout is negative")
	errUnsupportedPayloadType = errors.New("payload type cannot report its category")
	errPayloadType            = errors.New("payload is not of the subscriber's type")
	errPointerPayload         = errors.New("payload is a pointer")
	errPayloadPanicked        = errors.New("payload panicked")
	errInvalidQueueSize       = errors.New("event bus queue size is negative")
	errInvalidDeliveryTimeout = errors.New("event bus delivery timeout is negative")
)
