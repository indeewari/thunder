// Copyright 2026 The ThunderID Authors
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"context"

	"github.com/thunder-id/thunderid/internal/system/eventbus"
)

// Sink receives audit events, each with the envelope the bus filled in.
type Sink = eventbus.Subscriber[Payload]

// Subscribe registers sink for audit events under a stable id. The sink receives only the detail keys
// each event's catalog entry allows.
func Subscribe(bus eventbus.EventBusInterface, id string, sink Sink) error {
	if sink == nil {
		return errNilSink
	}
	return eventbus.Subscribe[Payload](bus, id, allowlistedSink{sink: sink})
}

// allowlistedSink hands each event to a sink with only the details its catalog entry allows.
type allowlistedSink struct {
	sink Sink
}

// Handle passes the event on with the details the catalog does not allow removed.
func (s allowlistedSink) Handle(ctx context.Context, env eventbus.Envelope, payload Payload) error {
	return s.sink.Handle(ctx, env, payload.withAllowedDetails(allowedDetails(env.Name)))
}
