// Copyright 2026 The ThunderID Authors
// SPDX-License-Identifier: Apache-2.0

package eventbus

import (
	"context"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/suite"
)

const (
	dropWarning      = "Subscriber queue is full, events are being dropped"
	failureWarning   = "Subscriber failed to handle an event"
	timeoutWarning   = "Subscriber timed out handling an event"
	panicWarning     = "Subscriber panicked while handling an event"
	abandonedWarning = "Event bus stopped before delivering queued events"
)

type SubscriptionTestSuite struct {
	busSuite
}

func TestSubscriptionTestSuite(t *testing.T) {
	suite.Run(t, new(SubscriptionTestSuite))
}

func (s *SubscriptionTestSuite) TestTimeoutIsCountedAndTheWorkerContinues() {
	bus := s.newBus(8, 30*time.Millisecond)
	defer s.shutdown(bus)
	var calls atomic.Int32
	rec := subscribe[payloadOne](&s.busSuite, bus, "flaky", func(ctx context.Context) error {
		if calls.Add(1) == 1 {
			<-ctx.Done()
			return ctx.Err()
		}
		return nil
	})

	s.Require().NoError(s.publish(bus, testEventName, payloadOne{}))
	s.Require().NoError(s.publish(bus, testEventName, payloadOne{}))

	s.eventually(func() bool {
		stats := s.stats(bus)[0]
		return stats.TimedOut == 1 && stats.Delivered == 1
	})
	envelopes, _ := rec.received()
	s.Equal([]uint64{2}, sequences(envelopes))
}

func (s *SubscriptionTestSuite) TestOnlyADeadlineErrorIsCountedAsTimedOut() {
	bus := s.newBus(8, 10*time.Millisecond)
	defer s.shutdown(bus)
	subscribe[payloadOne](&s.busSuite, bus, "late", func(ctx context.Context) error {
		<-ctx.Done()
		return errPayloadIncomplete
	})

	s.Require().NoError(s.publish(bus, testEventName, payloadOne{}))

	s.eventually(func() bool { return s.stats(bus)[0].Failed == 1 })
	s.Zero(s.stats(bus)[0].TimedOut)
}

func (s *SubscriptionTestSuite) TestPanicIsCountedAndTheWorkerContinues() {
	bus := s.newBus(8, time.Second)
	defer s.shutdown(bus)
	var calls atomic.Int32
	subscribe[payloadOne](&s.busSuite, bus, "panicky", func(context.Context) error {
		if calls.Add(1) == 1 {
			panic("boom")
		}
		return nil
	})

	s.Require().NoError(s.publish(bus, testEventName, payloadOne{}))
	s.Require().NoError(s.publish(bus, testEventName, payloadOne{}))

	s.eventually(func() bool {
		stats := s.stats(bus)[0]
		return stats.Panicked == 1 && stats.Delivered == 1
	})
}

func (s *SubscriptionTestSuite) TestDropWarningIsRateLimitedPerSubscriber() {
	readLog := s.captureLog()
	bus := s.newBus(1, time.Minute)
	firstStarted, secondStarted := make(chan struct{}), make(chan struct{})
	release := make(chan struct{})
	subscribe[payloadOne](&s.busSuite, bus, "first", blockingHook(firstStarted, release))
	subscribe[payloadOne](&s.busSuite, bus, "second", blockingHook(secondStarted, release))
	s.Require().NoError(s.publish(bus, testEventName, payloadOne{}))
	await(&s.busSuite, firstStarted)
	await(&s.busSuite, secondStarted)

	for range 5 {
		s.Require().NoError(s.publish(bus, testEventName, payloadOne{}))
	}
	s.Equal(2, strings.Count(readLog(), dropWarning), "one warning per subscriber")

	first := bus.(*eventBusService).subs["first"]
	first.dropLog.last.Store(time.Now().Add(-logInterval).UnixNano())
	s.Require().NoError(s.publish(bus, testEventName, payloadOne{}))
	s.Equal(3, strings.Count(readLog(), dropWarning), "the interval has passed for the first subscriber only")

	stats := s.stats(bus)
	s.Equal(uint64(5), stats[0].Dropped)
	s.Equal(uint64(5), stats[1].Dropped)
	close(release)
	s.shutdown(bus)
}

func (s *SubscriptionTestSuite) TestFailureTimeoutAndPanicLinesAreRateLimitedAndCountersExact() {
	readLog := s.captureLog()
	bus := s.newBus(16, 20*time.Millisecond)
	subscribe[payloadOne](&s.busSuite, bus, "failing", func(context.Context) error { return errPayloadIncomplete })
	subscribe[payloadOne](&s.busSuite, bus, "panicking", func(context.Context) error { panic("boom") })
	subscribe[payloadOne](&s.busSuite, bus, "slow", func(ctx context.Context) error {
		<-ctx.Done()
		return ctx.Err()
	})

	for range 3 {
		s.Require().NoError(s.publish(bus, testEventName, payloadOne{}))
	}

	// Stats are ordered by ID: failing, panicking, slow.
	s.eventually(func() bool {
		stats := s.stats(bus)
		return stats[0].Failed == 3 && stats[1].Panicked == 3 && stats[2].TimedOut == 3
	})
	output := readLog()
	s.Equal(1, strings.Count(output, failureWarning))
	s.Equal(1, strings.Count(output, panicWarning))
	s.Equal(1, strings.Count(output, timeoutWarning))
	s.Contains(output, "eventID=")
	s.Contains(output, "event="+testEventName)
	s.Contains(output, "category="+string(categoryOne))

	failing := bus.(*eventBusService).subs["failing"]
	failing.failureLog.last.Store(time.Now().Add(-logInterval).UnixNano())
	s.Require().NoError(s.publish(bus, testEventName, payloadOne{}))
	s.eventually(func() bool { return s.stats(bus)[0].Failed == 4 })
	s.Equal(2, strings.Count(readLog(), failureWarning))
	s.shutdown(bus)
}
