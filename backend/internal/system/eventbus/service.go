// Copyright 2026 The ThunderID Authors
// SPDX-License-Identifier: Apache-2.0

// Package eventbus publishes events to subscribers by category. An event carries one typed payload
// per category, and each subscriber receives only its own category's payload from a bounded queue.
package eventbus

import (
	"cmp"
	"context"
	"fmt"
	"maps"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/thunder-id/thunderid/internal/system/log"
	"github.com/thunder-id/thunderid/internal/system/utils"
)

// eventBusService is the in-process event bus.
type eventBusService struct {
	logger          *log.Logger
	source          string
	instanceID      string
	bootID          string
	queueSize       int
	timeout         time.Duration
	shutdownTimeout time.Duration
	catalog         map[string][]Category
	strict          bool
	// ctx is the parent of every delivery context. Stop cancels it once the shutdown timeout ends.
	ctx    context.Context
	cancel context.CancelFunc

	mu         sync.RWMutex
	closed     bool
	subs       map[string]*subscription
	byCategory map[Category][]*subscription
	sequences  map[Category]*atomic.Uint64
	wg         sync.WaitGroup
}

// newEventBusService builds a bus from a configuration whose defaults are already applied, and
// returns it with its stopper.
func newEventBusService(cfg Config, bootID string) (EventBusInterface, StopperInterface) {
	ctx, cancel := context.WithCancel(context.Background())
	bus := &eventBusService{
		logger:          componentLogger,
		source:          cfg.Source,
		instanceID:      cfg.InstanceID,
		bootID:          bootID,
		queueSize:       cfg.QueueSize,
		timeout:         cfg.DeliveryTimeout,
		shutdownTimeout: cfg.ShutdownTimeout,
		catalog:         cfg.Catalog,
		strict:          cfg.RejectUnregistered,
		ctx:             ctx,
		cancel:          cancel,
		subs:            make(map[string]*subscription),
		byCategory:      make(map[Category][]*subscription),
		sequences:       make(map[Category]*atomic.Uint64),
	}
	return bus, &stopper{bus: bus}
}

// Publish records the event for the subscribers of each category it carries. The envelope is
// stamped only when a category has a subscriber, so an event nobody receives costs validation alone.
func (s *eventBusService) Publish(ctx context.Context, evt *Event) error {
	if err := evt.validate(); err != nil {
		return err
	}
	if err := s.checkCatalog(evt); err != nil {
		return err
	}

	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.closed {
		return errBusClosed
	}

	var env Envelope
	stamped := false
	for category, payload := range evt.payloads {
		subscribers := s.byCategory[category]
		if len(subscribers) == 0 {
			continue
		}
		if !stamped {
			var err error
			if env, err = s.stamp(evt); err != nil {
				return err
			}
			stamped = true
		}
		env.Seq = s.sequences[category].Add(1)
		for _, sub := range subscribers {
			// A later at-least-once mode replaces this non-blocking send.
			select {
			case sub.queue <- delivery{env: env, payload: payload}:
			default:
				sub.noteDrop(ctx)
			}
		}
	}
	return nil
}

// Register adds a subscriber of a category and starts its worker.
func (s *eventBusService) Register(category Category, id string, handler Handler) error {
	if id == "" {
		return errEmptySubscriberID
	}
	if handler == nil {
		return errNilHandler
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return errBusClosed
	}
	if _, exists := s.subs[id]; exists {
		return errDuplicateSubscriberID
	}

	sub := &subscription{
		id:       id,
		category: category,
		handler:  handler,
		queue:    make(chan delivery, s.queueSize),
		logger:   s.logger.With(log.String("subscriberID", id), log.String("category", string(category))),
	}
	s.subs[id] = sub
	s.byCategory[category] = append(s.byCategory[category], sub)
	if _, exists := s.sequences[category]; !exists {
		s.sequences[category] = new(atomic.Uint64)
	}
	s.wg.Add(1)
	go sub.run(s)
	return nil
}

// Stats returns the counters of every subscriber ordered by id.
func (s *eventBusService) Stats() []SubscriberStats {
	s.mu.RLock()
	defer s.mu.RUnlock()

	stats := make([]SubscriberStats, 0, len(s.subs))
	for _, sub := range s.subs {
		stats = append(stats, sub.stats())
	}
	slices.SortFunc(stats, func(a, b SubscriberStats) int { return cmp.Compare(a.ID, b.ID) })
	return stats
}

// stop refuses new events, lets the queues drain within the shutdown timeout, then cancels the
// deliveries in flight and drops what is left.
func (s *eventBusService) stop() {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return
	}
	s.closed = true
	subs := slices.Collect(maps.Values(s.subs))
	for _, sub := range subs {
		close(sub.queue)
	}
	s.mu.Unlock()

	drained := s.waitForWorkers(s.shutdownTimeout)
	s.cancel()
	if drained {
		return
	}
	for _, sub := range subs {
		sub.abandonQueued()
	}
	s.waitForWorkers(shutdownGrace)
	for _, sub := range subs {
		sub.reportAbandoned()
	}
}

// checkCatalog rejects an event whose name is registered but lacks a required payload and, when
// unregistered names are rejected, an event whose name is not registered.
func (s *eventBusService) checkCatalog(evt *Event) error {
	required, registered := s.catalog[evt.envelope.Name]
	if !registered {
		if s.strict {
			return fmt.Errorf("%w: %q", errUnregisteredEvent, evt.envelope.Name)
		}
		return nil
	}
	for _, category := range required {
		if _, ok := evt.payloads[category]; !ok {
			return fmt.Errorf("%w: %q needs %q", errMissingPayload, evt.envelope.Name, category)
		}
	}
	return nil
}

// stamp returns the envelope of one publish of evt with the fields the bus owns filled in. An ID
// cannot be generated only when the clock is before the Unix epoch, and the event is then rejected
// rather than published under an ID that does not sort by time.
func (s *eventBusService) stamp(evt *Event) (Envelope, error) {
	id, err := utils.GenerateUUIDv7()
	if err != nil {
		return Envelope{}, fmt.Errorf("%w: %w", errEventID, err)
	}
	env := evt.envelope
	env.ID = id
	env.Time = time.Now().UTC().Truncate(time.Microsecond)
	env.Source = s.source
	env.InstanceID = s.instanceID
	env.BootID = s.bootID
	return env, nil
}

// waitForWorkers reports whether every worker finished within timeout.
func (s *eventBusService) waitForWorkers(timeout time.Duration) bool {
	done := make(chan struct{})
	go func() {
		s.wg.Wait()
		close(done)
	}()
	select {
	case <-done:
		return true
	case <-time.After(timeout):
		return false
	}
}

// stopper is the StopperInterface of a bus, kept apart so that a holder of the bus cannot stop it.
type stopper struct {
	bus *eventBusService
}

// Stop implements StopperInterface.
func (s *stopper) Stop() {
	s.bus.stop()
}
