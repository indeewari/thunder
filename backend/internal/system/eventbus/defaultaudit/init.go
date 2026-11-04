// Copyright 2026 The ThunderID Authors
// SPDX-License-Identifier: Apache-2.0

// Package defaultaudit builds the event bus a server binary publishes audit events on, with the
// default sink that writes them to standard output.
package defaultaudit

import (
	"fmt"
	"time"

	"github.com/thunder-id/thunderid/internal/system/eventbus"
	"github.com/thunder-id/thunderid/internal/system/eventbus/audit"
	"github.com/thunder-id/thunderid/internal/system/eventbus/stdoutsink"
)

// stdoutSubscriberID is the stable subscriber ID of the stdout sink.
const stdoutSubscriberID = "audit-stdout"

// Initialize builds the event bus with the audit catalog, refusing an event outside it, and
// subscribes the stdout sink when audit is on. With audit off the bus has no sink: an event is still
// validated, then dropped, so a publisher never checks whether audit is on. An invalid audit or marker
// configuration is refused whether audit is on or off.
func Initialize(cfg Config) (eventbus.EventBusInterface, eventbus.StopperInterface, error) {
	sink, err := stdoutsink.Initialize(cfg.LogType)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to initialize the audit stdout sink: %w", err)
	}

	bus, stopper, err := eventbus.Initialize(eventbus.Config{
		Source:          cfg.Source,
		InstanceID:      cfg.Audit.InstanceID,
		QueueSize:       cfg.Audit.QueueSize,
		DeliveryTimeout: time.Duration(cfg.Audit.DeliveryTimeoutSeconds) * time.Second,
		ShutdownTimeout: cfg.ShutdownTimeout,
		Delivery: map[eventbus.Category]eventbus.DeliveryMode{
			audit.CategoryAudit: eventbus.DeliveryMode(cfg.Audit.Delivery),
		},
		Catalog:            audit.Catalog(),
		RejectUnregistered: true,
	})
	if err != nil {
		return nil, nil, fmt.Errorf("failed to initialize the audit event bus: %w", err)
	}
	if !cfg.Audit.IsEnabled() {
		return bus, stopper, nil
	}

	if err := audit.Subscribe(bus, stdoutSubscriberID, sink); err != nil {
		return nil, nil, fmt.Errorf("failed to subscribe the audit stdout sink: %w", err)
	}
	return bus, stopper, nil
}
