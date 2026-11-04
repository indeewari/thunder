// Copyright 2026 The ThunderID Authors
// SPDX-License-Identifier: Apache-2.0

package eventbus

import (
	"fmt"
	"os"
	"slices"

	"github.com/thunder-id/thunderid/internal/system/utils"
)

// Initialize creates the event bus and the stopper that only the composition root holds.
func Initialize(cfg Config) (EventBusInterface, StopperInterface, error) {
	if cfg.Source == "" {
		return nil, nil, errEmptySource
	}
	if cfg.QueueSize < 0 {
		return nil, nil, errInvalidQueueSize
	}
	if cfg.DeliveryTimeout < 0 {
		return nil, nil, errInvalidDeliveryTimeout
	}
	if cfg.ShutdownTimeout < 0 {
		return nil, nil, errInvalidShutdownTimeout
	}
	// Only best effort is built, so a deployment never assumes a guarantee the build cannot give.
	for category, mode := range cfg.Delivery {
		if mode != "" && mode != DeliveryBestEffort {
			return nil, nil, fmt.Errorf("%w: %q for category %q", errUnsupportedDelivery, mode, category)
		}
	}

	if cfg.QueueSize == 0 {
		cfg.QueueSize = defaultQueueSize
	}
	if cfg.DeliveryTimeout == 0 {
		cfg.DeliveryTimeout = defaultDeliveryTimeout
	}
	if cfg.ShutdownTimeout == 0 {
		cfg.ShutdownTimeout = defaultShutdownTimeout
	}
	if cfg.InstanceID == "" {
		hostName, err := os.Hostname()
		if err != nil {
			return nil, nil, fmt.Errorf("%w: %w", errInstanceID, err)
		}
		cfg.InstanceID = hostName
	}

	catalog := make(map[string][]Category, len(cfg.Catalog))
	for name, categories := range cfg.Catalog {
		catalog[name] = slices.Clone(categories)
	}
	cfg.Catalog = catalog

	bus, busStopper := newEventBusService(cfg, utils.GenerateUUID())
	return bus, busStopper, nil
}
