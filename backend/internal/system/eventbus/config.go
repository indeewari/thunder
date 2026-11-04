// Copyright 2026 The ThunderID Authors
// SPDX-License-Identifier: Apache-2.0

package eventbus

import "time"

// Config configures the event bus.
type Config struct {
	// Source names the publishing binary, for example server or control_plane. It must not be empty.
	Source string
	// InstanceID identifies this process. Empty selects the host name.
	InstanceID string
	// QueueSize is the capacity of each subscriber queue. Zero selects the default, because the server
	// configuration merge cannot tell zero from unset.
	QueueSize int
	// DeliveryTimeout bounds one delivery to a subscriber. Zero selects the default.
	DeliveryTimeout time.Duration
	// ShutdownTimeout bounds how long Stop lets the queues drain. Stop then waits a fixed grace for the
	// canceled deliveries, so its total wait is ShutdownTimeout plus that grace. Zero selects the default.
	ShutdownTimeout time.Duration
	// Delivery is the delivery guarantee per category. A category not listed, or listed with "", is
	// best effort, the only guarantee supported.
	Delivery map[Category]DeliveryMode
	// Catalog maps an event name to the categories an event of that name must carry a payload for.
	Catalog map[string][]Category
	// RejectUnregistered makes Publish reject an event whose name is not in the catalog.
	RejectUnregistered bool
}
