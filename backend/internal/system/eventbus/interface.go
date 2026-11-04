// Copyright 2026 The ThunderID Authors
// SPDX-License-Identifier: Apache-2.0

package eventbus

import "context"

// EventBusInterface publishes events and registers subscribers.
type EventBusInterface interface {
	// Publish records the event for every subscriber of its categories and returns. It never runs
	// subscriber code, and a slow or full subscriber never makes it return an error.
	Publish(ctx context.Context, evt *Event) error
	// Register adds a subscriber of a category under a stable id. Prefer Subscribe, which is typed.
	Register(category Category, id string, handler Handler) error
}

// StopperInterface stops the event bus. Only the composition root holds it.
type StopperInterface interface {
	// Stop drains within the shutdown timeout, then cancels and drops the rest, so it waits at most the
	// shutdown timeout plus a fixed grace. A second call returns at once, even while the first drains.
	Stop()
}

// Payload is the data an event carries for one category. It must be a value, not a pointer, and must
// not be changed after Publish. A subscriber must not retain state the payload shares.
type Payload interface {
	// Category returns the category the payload puts its event in.
	Category() Category
}

// PayloadValidator is implemented by a payload whose category has required fields.
type PayloadValidator interface {
	// Validate reports why the payload cannot be published.
	Validate() error
}

// Subscriber receives the events of the category of P.
type Subscriber[P Payload] interface {
	// Handle processes one event and returns an error when delivery failed. It must honor ctx: the
	// timeout is cooperative, and a handler that ignores ctx keeps its worker.
	Handle(ctx context.Context, env Envelope, payload P) error
}
