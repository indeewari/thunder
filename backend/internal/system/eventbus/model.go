// Copyright 2026 The ThunderID Authors
// SPDX-License-Identifier: Apache-2.0

package eventbus

import (
	"context"
	"time"
)

// Category is the purpose of an event, for example audit. A payload of a category puts the event in it.
type Category string

// DeliveryMode is the guarantee a category is delivered with.
type DeliveryMode string

// Envelope holds the fields the framework fills in on every event.
type Envelope struct {
	// ID is unique per event, a UUID v7 so that IDs sort by time.
	ID string
	// Name identifies the action attempted, for example user.create.
	Name string
	// Time is when the event was published, in UTC to the microsecond.
	Time time.Time
	// TraceID is the correlation ID of the request. A caller can supply it, so it is not trusted.
	TraceID string
	// TraceParent is the W3C trace context of the request, empty when it carried no valid one. A caller
	// supplies it, so it is not trusted.
	TraceParent string
	// DeploymentID is the deployment the event belongs to.
	DeploymentID string
	// Source names the binary that published the event.
	Source string
	// InstanceID identifies the host of the process that published the event.
	InstanceID string
	// BootID identifies one run of the process.
	BootID string
	// Seq is unique per category per boot and only a dropped event leaves a gap. Delivery order across
	// concurrent publishers is not guaranteed, so a consumer sorts by Seq within (instance ID, boot ID,
	// category).
	Seq uint64
}

// Handler receives an event for one subscriber. It must honor ctx: the timeout is cooperative, and a
// handler that ignores ctx keeps its worker.
type Handler func(ctx context.Context, env Envelope, payload Payload) error

// delivery is one event on its way to one subscriber, with only that subscriber's payload.
type delivery struct {
	env     Envelope
	payload Payload
}

// SubscriberStats are the counters of one subscriber.
type SubscriberStats struct {
	ID        string
	Category  Category
	Delivered uint64
	Dropped   uint64
	Failed    uint64
	TimedOut  uint64
	Panicked  uint64
}
