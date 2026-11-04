// Copyright 2026 The ThunderID Authors
// SPDX-License-Identifier: Apache-2.0

package eventbus

import (
	"context"
	"reflect"

	"github.com/thunder-id/thunderid/internal/system/log"
)

// componentLogger is the logger of the package, shared by the bus and its helpers.
var componentLogger = log.GetLogger().With(log.String(log.LoggerKeyComponentName, "EventBus"))

// TryPublish publishes evt on bus and logs a failed publish. A failed publish never fails the
// operation the event describes, so the caller has nothing to branch on.
func TryPublish(ctx context.Context, bus EventBusInterface, evt *Event) {
	if err := bus.Publish(ctx, evt); err != nil {
		name := evt.Name()
		if !isValidEventName(name) {
			name = invalidEventName
		}
		componentLogger.Warn(ctx, "Failed to publish an event", log.String("event", name), log.Error(err))
	}
}

// Subscribe registers sub for the category of P under a stable id. The id must not change across
// restarts or releases. P must be a value type whose Category works on its zero value.
func Subscribe[P Payload](bus EventBusInterface, id string, sub Subscriber[P]) error {
	if sub == nil {
		return errNilHandler
	}
	category, err := categoryOf[P]()
	if err != nil {
		return err
	}
	return bus.Register(category, id, func(ctx context.Context, env Envelope, payload Payload) error {
		typed, ok := payload.(P)
		if !ok {
			return errPayloadType
		}
		return sub.Handle(ctx, env, typed)
	})
}

// isValidEventName reports whether name follows the event name grammar and length limit.
func isValidEventName(name string) bool {
	return len(name) <= maxEventNameLength && eventNamePattern.MatchString(name)
}

// categoryOf returns the category of the payload type P, read from its zero value. An interface or
// pointer type is refused, because With never accepts a payload of one.
func categoryOf[P Payload]() (Category, error) {
	switch reflect.TypeFor[P]().Kind() {
	case reflect.Interface, reflect.Pointer:
		return "", errUnsupportedPayloadType
	}
	var zero P
	category, err := payloadCategory(zero)
	if err != nil {
		return "", errUnsupportedPayloadType
	}
	return category, nil
}

// payloadCategory returns the category of payload, turning a panic in its Category into an error.
func payloadCategory(payload Payload) (category Category, err error) {
	defer func() {
		if recover() != nil {
			err = errPayloadPanicked
		}
	}()
	return payload.Category(), nil
}

// validatePayload runs the payload's own validation, turning a panic into an error.
func validatePayload(validator PayloadValidator) (err error) {
	defer func() {
		if recover() != nil {
			err = errPayloadPanicked
		}
	}()
	return validator.Validate()
}
