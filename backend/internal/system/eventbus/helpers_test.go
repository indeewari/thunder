// Copyright 2026 The ThunderID Authors
// SPDX-License-Identifier: Apache-2.0

package eventbus

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/suite"

	"github.com/thunder-id/thunderid/internal/system/log"
	"github.com/thunder-id/thunderid/internal/system/log/rollingfile"
)

const (
	categoryOne Category = "test_one"
	categoryTwo Category = "test_two"

	testSource     = "server"
	testInstanceID = "test-instance"
	testEventName  = "user.created"
	waitLimit      = 3 * time.Second
	logFileName    = "eventbus.log"
)

var errPayloadIncomplete = errors.New("payload lacks a required field")

type payloadOne struct{ value string }

func (payloadOne) Category() Category { return categoryOne }

type payloadTwo struct{ value string }

func (payloadTwo) Category() Category { return categoryTwo }

// pointerPayload is a payload published through a pointer.
type pointerPayload struct{ category Category }

func (p *pointerPayload) Category() Category { return p.category }

// panickingPayload panics when asked for its category.
type panickingPayload struct{}

func (panickingPayload) Category() Category { panic("category") }

// panickingValidatorPayload panics while validating.
type panickingValidatorPayload struct{}

func (panickingValidatorPayload) Category() Category { return categoryOne }

func (panickingValidatorPayload) Validate() error { panic("validate") }

// checkedPayload is a payload whose category requires a value.
type checkedPayload struct{ value string }

func (checkedPayload) Category() Category { return categoryOne }

func (p checkedPayload) Validate() error {
	if p.value == "" {
		return errPayloadIncomplete
	}
	return nil
}

// recorder keeps what a subscriber mock received. The mock's own call list is not read while a
// worker may still be calling it.
type recorder[P Payload] struct {
	mu        sync.Mutex
	envelopes []Envelope
	payloads  []P
}

func (r *recorder[P]) add(env Envelope, payload P) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.envelopes = append(r.envelopes, env)
	r.payloads = append(r.payloads, payload)
}

func (r *recorder[P]) count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.envelopes)
}

func (r *recorder[P]) received() ([]Envelope, []P) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]Envelope(nil), r.envelopes...), append([]P(nil), r.payloads...)
}

// busSuite holds the helpers the bus suites share.
type busSuite struct {
	suite.Suite
	stoppers map[EventBusInterface]StopperInterface
}

func (s *busSuite) newBus(queueSize int, timeout time.Duration) EventBusInterface {
	return s.newBusWith(Config{QueueSize: queueSize, DeliveryTimeout: timeout})
}

// newBusWith fills in the source and instance ID unless cfg sets them, and stops the bus when the
// test ends.
func (s *busSuite) newBusWith(cfg Config) EventBusInterface {
	if cfg.Source == "" {
		cfg.Source = testSource
	}
	if cfg.InstanceID == "" {
		cfg.InstanceID = testInstanceID
	}
	bus, stopper, err := Initialize(cfg)
	s.Require().NoError(err)
	if s.stoppers == nil {
		s.stoppers = make(map[EventBusInterface]StopperInterface)
	}
	s.stoppers[bus] = stopper
	s.T().Cleanup(stopper.Stop)
	return bus
}

func (s *busSuite) shutdown(bus EventBusInterface) {
	s.stoppers[bus].Stop()
}

// stats reads the counters through the concrete bus, which is where Stats lives.
func (s *busSuite) stats(bus EventBusInterface) []SubscriberStats {
	return bus.(*eventBusService).Stats()
}

func (s *busSuite) eventually(condition func() bool) {
	s.Require().Eventually(condition, waitLimit, 5*time.Millisecond)
}

// await receives from ch and fails the test unless a value arrives within waitLimit.
func await[T any](s *busSuite, ch <-chan T) T {
	select {
	case value := <-ch:
		return value
	case <-time.After(waitLimit):
		s.FailNow("nothing received in time")
	}
	var zero T
	return zero
}

// completes runs f and fails the test unless f returns within waitLimit.
func (s *busSuite) completes(f func()) {
	done := make(chan struct{})
	go func() {
		defer close(done)
		f()
	}()
	select {
	case <-done:
	case <-time.After(waitLimit):
		s.FailNow("did not complete in time")
	}
}

func (s *busSuite) publish(bus EventBusInterface, name string, payloads ...Payload) error {
	return bus.Publish(context.Background(), s.event(context.Background(), name, payloads...))
}

func (s *busSuite) event(ctx context.Context, name string, payloads ...Payload) *Event {
	evt := NewEvent(ctx, name)
	for _, payload := range payloads {
		evt = evt.With(payload)
	}
	return evt
}

// subscribe registers a subscriber mock for the category of P that runs hook, when set, and records
// the event when hook returns nil. hook may block, fail or panic.
func subscribe[P Payload](s *busSuite, bus EventBusInterface, id string,
	hook func(ctx context.Context) error) *recorder[P] {
	rec := &recorder[P]{}
	sub := NewSubscriberMock[P](s.T())
	sub.EXPECT().Handle(mock.Anything, mock.Anything, mock.Anything).
		RunAndReturn(func(ctx context.Context, env Envelope, payload P) error {
			if hook != nil {
				if err := hook(ctx); err != nil {
					return err
				}
			}
			rec.add(env, payload)
			return nil
		}).Maybe()
	s.Require().NoError(Subscribe[P](bus, id, sub))
	return rec
}

// blockingHook blocks every delivery until release is closed and signals the first one on started.
func blockingHook(started chan<- struct{}, release <-chan struct{}) func(context.Context) error {
	var once sync.Once
	return func(context.Context) error {
		once.Do(func() { close(started) })
		<-release
		return nil
	}
}

// captureLog sends the process logger to a file until the test ends and returns a reader for it.
func (s *busSuite) captureLog() func() string {
	dir := s.T().TempDir()
	s.Require().NoError(log.GetLogger().Configure(log.OutputOptions{
		FileEnabled: true,
		File:        rollingfile.Config{Path: filepath.Join(dir, logFileName)},
	}))
	s.T().Cleanup(func() {
		s.NoError(log.GetLogger().Configure(log.OutputOptions{ConsoleEnabled: true}))
	})
	return func() string {
		content, err := fs.ReadFile(os.DirFS(dir), logFileName)
		s.Require().NoError(err)
		return string(content)
	}
}
