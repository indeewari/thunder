// Copyright 2026 The ThunderID Authors
// SPDX-License-Identifier: Apache-2.0

package eventbus

import (
	"context"
	"fmt"
	"reflect"

	sysContext "github.com/thunder-id/thunderid/internal/system/context"
	"github.com/thunder-id/thunderid/internal/system/deployment"
)

// traceParentKey is the context key of the request's W3C traceparent.
type traceParentKey struct{}

// WithTraceParent returns ctx carrying the request's W3C traceparent, which NewEvent copies into the
// envelope. A value that is not a valid version 00 traceparent, or has an all-zero trace or parent ID,
// is ignored, and none is ever generated.
func WithTraceParent(ctx context.Context, traceParent string) context.Context {
	if !isValidTraceParent(traceParent) {
		return ctx
	}
	return context.WithValue(ctx, traceParentKey{}, traceParent)
}

// Event is one fact with the payloads of the categories it belongs to.
type Event struct {
	envelope Envelope
	payloads map[Category]Payload
	err      error
}

// NewEvent starts an event named name, taking the request's trace and deployment from ctx. A
// malformed event is reported by Publish, so the call chain stays fluent.
func NewEvent(ctx context.Context, name string) *Event {
	traceID, _ := ctx.Value(sysContext.TraceIDKey).(string)
	traceParent, _ := ctx.Value(traceParentKey{}).(string)
	evt := &Event{
		envelope: Envelope{
			Name:         name,
			TraceID:      traceID,
			TraceParent:  traceParent,
			DeploymentID: deployment.Resolve(ctx),
		},
		payloads: make(map[Category]Payload),
	}
	if !isValidEventName(name) {
		evt.err = errInvalidEventName
	}
	return evt
}

// With attaches a payload, which puts the event in the payload's category.
func (e *Event) With(payload Payload) *Event {
	if e.err != nil {
		return e
	}
	if payload == nil {
		e.err = errNilPayload
		return e
	}
	// Payloads are passed by value, so no subscriber can change what another receives.
	if reflect.ValueOf(payload).Kind() == reflect.Pointer {
		e.err = errPointerPayload
		return e
	}
	category, err := payloadCategory(payload)
	if err != nil {
		e.err = err
		return e
	}
	if _, exists := e.payloads[category]; exists {
		e.err = errDuplicateCategory
		return e
	}
	e.payloads[category] = payload
	return e
}

// Name returns the event name, empty for a nil event.
func (e *Event) Name() string {
	if e == nil {
		return ""
	}
	return e.envelope.Name
}

// validate reports why the event cannot be published, including a payload that fails its own rules.
func (e *Event) validate() error {
	if e == nil {
		return errNilEvent
	}
	if e.err != nil {
		return e.err
	}
	if len(e.payloads) == 0 {
		return errNoPayload
	}
	for category, payload := range e.payloads {
		validator, ok := payload.(PayloadValidator)
		if !ok {
			continue
		}
		if err := validatePayload(validator); err != nil {
			return fmt.Errorf("%w: %q: %w", errInvalidPayload, category, err)
		}
	}
	return nil
}
