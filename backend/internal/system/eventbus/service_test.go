// Copyright 2026 The ThunderID Authors
// SPDX-License-Identifier: Apache-2.0

package eventbus

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/suite"

	sysContext "github.com/thunder-id/thunderid/internal/system/context"
	"github.com/thunder-id/thunderid/internal/system/deployment"
	"github.com/thunder-id/thunderid/internal/system/utils"
)

type EventBusServiceTestSuite struct {
	busSuite
}

func TestEventBusServiceTestSuite(t *testing.T) {
	suite.Run(t, new(EventBusServiceTestSuite))
}

func (s *EventBusServiceTestSuite) TestRoutesEachCategoryToItsOwnSubscribersOnly() {
	bus := s.newBus(8, time.Second)
	defer s.shutdown(bus)
	one := subscribe[payloadOne](&s.busSuite, bus, "one", nil)
	two := subscribe[payloadTwo](&s.busSuite, bus, "two", nil)

	s.Require().NoError(s.publish(bus, "user.created", payloadOne{value: "a"}))
	s.Require().NoError(s.publish(bus, "user.updated", payloadTwo{value: "b"}))
	s.Require().NoError(s.publish(bus, "user.deleted", payloadOne{value: "c"}, payloadTwo{value: "d"}))

	s.eventually(func() bool { return one.count() == 2 && two.count() == 2 })
	_, onePayloads := one.received()
	_, twoPayloads := two.received()
	s.Equal([]payloadOne{{value: "a"}, {value: "c"}}, onePayloads)
	s.Equal([]payloadTwo{{value: "b"}, {value: "d"}}, twoPayloads)
}

func (s *EventBusServiceTestSuite) TestEventInSeveralCategoriesReachesEachSubscriberOnce() {
	bus := s.newBus(8, time.Second)
	firstOne := subscribe[payloadOne](&s.busSuite, bus, "one-a", nil)
	secondOne := subscribe[payloadOne](&s.busSuite, bus, "one-b", nil)
	two := subscribe[payloadTwo](&s.busSuite, bus, "two", nil)

	s.Require().NoError(s.publish(bus, testEventName, payloadOne{value: "a"}, payloadTwo{value: "b"}))
	s.shutdown(bus)

	s.Equal(1, firstOne.count())
	s.Equal(1, secondOne.count())
	s.Equal(1, two.count())
	oneEnvelopes, _ := firstOne.received()
	twoEnvelopes, _ := two.received()
	s.Equal(oneEnvelopes[0].ID, twoEnvelopes[0].ID)
}

func (s *EventBusServiceTestSuite) TestSubscriberNeverSeesAnotherCategoryPayload() {
	bus := s.newBus(8, time.Second)
	defer s.shutdown(bus)
	var received []Payload
	var mu sync.Mutex
	err := bus.Register(categoryOne, "raw", func(_ context.Context, _ Envelope, payload Payload) error {
		mu.Lock()
		defer mu.Unlock()
		received = append(received, payload)
		return nil
	})
	s.Require().NoError(err)

	s.Require().NoError(s.publish(bus, testEventName, payloadOne{value: "a"}, payloadTwo{value: "b"}))
	s.eventually(func() bool { return s.stats(bus)[0].Delivered == 1 })

	mu.Lock()
	defer mu.Unlock()
	s.Equal([]Payload{payloadOne{value: "a"}}, received)
}

func (s *EventBusServiceTestSuite) TestEnvelopeCarriesEveryField() {
	bus := s.newBus(8, time.Second)
	defer s.shutdown(bus)
	rec := subscribe[payloadOne](&s.busSuite, bus, "one", nil)
	ctx := sysContext.WithTraceID(context.Background(), "trace-1")
	ctx = deployment.WithID(ctx, "deployment-1")
	ctx = WithTraceParent(ctx, validTraceParent)

	before := time.Now().UTC().Truncate(time.Microsecond)
	s.Require().NoError(bus.Publish(ctx, s.event(ctx, testEventName, payloadOne{})))
	after := time.Now().UTC()

	s.eventually(func() bool { return rec.count() == 1 })
	envelopes, _ := rec.received()
	env := envelopes[0]
	s.True(utils.IsValidUUID(env.ID), env.ID)
	s.Equal(byte('7'), env.ID[14], "event ID is a UUID v7")
	s.Equal(testEventName, env.Name)
	s.Equal(time.UTC, env.Time.Location())
	s.Zero(env.Time.Nanosecond()%int(time.Microsecond), "time is truncated to the microsecond")
	s.False(env.Time.Before(before))
	s.False(env.Time.After(after))
	s.Equal("trace-1", env.TraceID)
	s.Equal(validTraceParent, env.TraceParent)
	s.Equal("deployment-1", env.DeploymentID)
	s.Equal(testSource, env.Source)
	s.Equal(testInstanceID, env.InstanceID)
	s.Equal(bus.(*eventBusService).bootID, env.BootID)
	s.Equal(uint64(1), env.Seq)
}

func (s *EventBusServiceTestSuite) TestEachPublishGetsItsOwnID() {
	bus := s.newBus(8, time.Second)
	defer s.shutdown(bus)
	rec := subscribe[payloadOne](&s.busSuite, bus, "one", nil)
	evt := s.event(context.Background(), testEventName, payloadOne{})

	s.Require().NoError(bus.Publish(context.Background(), evt))
	s.Require().NoError(bus.Publish(context.Background(), evt))

	s.eventually(func() bool { return rec.count() == 2 })
	envelopes, _ := rec.received()
	s.NotEqual(envelopes[0].ID, envelopes[1].ID)
}

func (s *EventBusServiceTestSuite) TestSequenceCountsPerCategory() {
	bus := s.newBus(8, time.Second)
	defer s.shutdown(bus)
	one := subscribe[payloadOne](&s.busSuite, bus, "one", nil)
	two := subscribe[payloadTwo](&s.busSuite, bus, "two", nil)

	for range 3 {
		s.Require().NoError(s.publish(bus, testEventName, payloadOne{}))
	}
	s.Require().NoError(s.publish(bus, testEventName, payloadTwo{}))
	s.Require().NoError(s.publish(bus, testEventName, payloadOne{}, payloadTwo{}))

	s.eventually(func() bool { return one.count() == 4 && two.count() == 2 })
	oneEnvelopes, _ := one.received()
	twoEnvelopes, _ := two.received()
	s.Equal([]uint64{1, 2, 3, 4}, sequences(oneEnvelopes))
	s.Equal([]uint64{1, 2}, sequences(twoEnvelopes))
	s.Equal(oneEnvelopes[0].BootID, twoEnvelopes[0].BootID)
}

func (s *EventBusServiceTestSuite) TestPublishWithNoSubscriberCostsNoSequence() {
	bus := s.newBus(8, time.Second)
	defer s.shutdown(bus)

	s.Require().NoError(s.publish(bus, testEventName, payloadOne{}))
	one := subscribe[payloadOne](&s.busSuite, bus, "one", nil)
	s.Require().NoError(s.publish(bus, testEventName, payloadOne{}))

	s.eventually(func() bool { return one.count() == 1 })
	envelopes, _ := one.received()
	s.Equal(uint64(1), envelopes[0].Seq)
}

func (s *EventBusServiceTestSuite) TestPublishNeverBlocksOnASlowSubscriberAndOthersAreUnaffected() {
	bus := s.newBus(2, time.Minute)
	started := make(chan struct{})
	release := make(chan struct{})
	defer close(release)
	subscribe[payloadOne](&s.busSuite, bus, "slow", blockingHook(started, release))
	fast := subscribe[payloadOne](&s.busSuite, bus, "fast", nil)

	s.Require().NoError(s.publish(bus, testEventName, payloadOne{}))
	await(&s.busSuite, started)
	s.completes(func() {
		for range 10 {
			s.NoError(s.publish(bus, testEventName, payloadOne{}))
		}
	})

	// Stats are ordered by ID, so fast comes first.
	s.eventually(func() bool {
		stats := s.stats(bus)
		return stats[0].Delivered+stats[0].Dropped == 11
	})
	s.EqualValues(s.stats(bus)[0].Delivered, fast.count())
	s.Equal(uint64(8), s.stats(bus)[1].Dropped)
}

func (s *EventBusServiceTestSuite) TestFullQueueDropsCountsAndLeavesAGapInTheSequence() {
	bus := s.newBus(1, time.Minute)
	started := make(chan struct{})
	release := make(chan struct{})
	rec := subscribe[payloadOne](&s.busSuite, bus, "slow", blockingHook(started, release))

	s.Require().NoError(s.publish(bus, testEventName, payloadOne{}))
	await(&s.busSuite, started)
	for range 5 {
		s.Require().NoError(s.publish(bus, testEventName, payloadOne{}))
	}

	s.Equal(uint64(4), s.stats(bus)[0].Dropped)
	close(release)
	s.eventually(func() bool { return rec.count() == 2 })
	s.Require().NoError(s.publish(bus, testEventName, payloadOne{}))
	s.eventually(func() bool { return rec.count() == 3 })
	envelopes, _ := rec.received()
	s.Equal([]uint64{1, 2, 7}, sequences(envelopes))
	s.shutdown(bus)
}

func (s *EventBusServiceTestSuite) TestFailureIsCountedAndDoesNotAffectOtherSubscribers() {
	bus := s.newBus(8, time.Second)
	defer s.shutdown(bus)
	subscribe[payloadOne](&s.busSuite, bus, "failing", func(context.Context) error { return errPayloadIncomplete })
	healthy := subscribe[payloadOne](&s.busSuite, bus, "healthy", nil)

	s.Require().NoError(s.publish(bus, testEventName, payloadOne{}))

	s.eventually(func() bool { return healthy.count() == 1 && s.stats(bus)[0].Failed == 1 })
}

func (s *EventBusServiceTestSuite) TestEachSubscriberHandlesOneEventAtATime() {
	bus := s.newBus(64, time.Second)
	var active, maxActive atomic.Int32
	rec := subscribe[payloadOne](&s.busSuite, bus, "serial", func(context.Context) error {
		now := active.Add(1)
		for {
			current := maxActive.Load()
			if now <= current || maxActive.CompareAndSwap(current, now) {
				break
			}
		}
		time.Sleep(time.Millisecond)
		active.Add(-1)
		return nil
	})

	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() {
			for range 5 {
				s.NoError(s.publish(bus, testEventName, payloadOne{}))
			}
		})
	}
	wg.Wait()

	s.eventually(func() bool { return rec.count() == 40 })
	s.Equal(int32(1), maxActive.Load())
	s.shutdown(bus)
}

func (s *EventBusServiceTestSuite) TestStopDrainsQueuedEvents() {
	bus := s.newBus(16, time.Second)
	rec := subscribe[payloadOne](&s.busSuite, bus, "drain", nil)
	for range 10 {
		s.Require().NoError(s.publish(bus, testEventName, payloadOne{}))
	}

	s.shutdown(bus)

	s.Equal(10, rec.count())
}

func (s *EventBusServiceTestSuite) TestStopCancelsInFlightDeliveryAndDropsWhatIsQueued() {
	readLog := s.captureLog()
	bus := s.newBusWith(Config{QueueSize: 16, DeliveryTimeout: time.Minute, ShutdownTimeout: 50 * time.Millisecond})
	started := make(chan struct{})
	stopped := make(chan error, 1)
	err := bus.Register(categoryOne, "stuck", func(ctx context.Context, _ Envelope, _ Payload) error {
		close(started)
		<-ctx.Done()
		stopped <- ctx.Err()
		return errPayloadIncomplete
	})
	s.Require().NoError(err)
	for range 3 {
		s.Require().NoError(s.publish(bus, testEventName, payloadOne{}))
	}
	await(&s.busSuite, started)

	s.completes(func() { s.shutdown(bus) })

	s.ErrorIs(await(&s.busSuite, stopped), context.Canceled)
	stats := s.stats(bus)[0]
	s.Equal(uint64(2), stats.Dropped)
	s.Equal(uint64(1), stats.Failed)
	s.Zero(stats.TimedOut)
	s.Equal(1, strings.Count(readLog(), abandonedWarning))
	s.Contains(readLog(), "abandoned=2")
	s.Contains(readLog(), errPayloadIncomplete.Error())
}

func (s *EventBusServiceTestSuite) TestStopIsBoundedWhenAHandlerIgnoresCancellation() {
	readLog := s.captureLog()
	bus := s.newBusWith(Config{QueueSize: 16, DeliveryTimeout: time.Minute, ShutdownTimeout: 50 * time.Millisecond})
	started := make(chan struct{})
	release := make(chan struct{})
	defer close(release)
	subscribe[payloadOne](&s.busSuite, bus, "stuck", blockingHook(started, release))
	for range 3 {
		s.Require().NoError(s.publish(bus, testEventName, payloadOne{}))
	}
	await(&s.busSuite, started)

	s.completes(func() { s.shutdown(bus) })

	s.Equal(uint64(2), s.stats(bus)[0].Dropped)
	s.Contains(readLog(), abandonedWarning)
}

func (s *EventBusServiceTestSuite) TestSecondStopReturnsWithoutWaitingForTheFirst() {
	bus := s.newBusWith(Config{QueueSize: 16, DeliveryTimeout: time.Minute, ShutdownTimeout: time.Minute})
	started := make(chan struct{})
	release := make(chan struct{})
	releaseHandler := sync.OnceFunc(func() { close(release) })
	defer releaseHandler()
	rec := subscribe[payloadOne](&s.busSuite, bus, "stuck", blockingHook(started, release))
	s.Require().NoError(s.publish(bus, testEventName, payloadOne{}))
	s.Require().NoError(s.publish(bus, testEventName, payloadOne{}))
	await(&s.busSuite, started)

	firstDone := make(chan struct{})
	go func() {
		defer close(firstDone)
		s.shutdown(bus)
	}()
	service := bus.(*eventBusService)
	s.eventually(func() bool {
		service.mu.RLock()
		defer service.mu.RUnlock()
		return service.closed
	})
	s.completes(func() { s.shutdown(bus) })

	select {
	case <-firstDone:
		s.Fail("the first Stop returned while its handler was still blocked")
	default:
	}
	releaseHandler()
	await(&s.busSuite, firstDone)
	s.Equal(2, rec.count())
	s.Zero(s.stats(bus)[0].Dropped)
}

func (s *EventBusServiceTestSuite) TestPublishAndRegisterAfterStopAreRejected() {
	bus := s.newBus(8, time.Second)
	s.shutdown(bus)

	s.ErrorIs(s.publish(bus, testEventName, payloadOne{}), errBusClosed)
	s.ErrorIs(bus.Register(categoryOne, "late", discard), errBusClosed)
}

func (s *EventBusServiceTestSuite) TestSubscriberContextCarriesTheEventTraceAndDeployment() {
	bus := s.newBus(8, time.Second)
	received := make(chan [2]string, 1)
	err := bus.Register(categoryOne, "one", func(ctx context.Context, _ Envelope, _ Payload) error {
		received <- [2]string{sysContext.GetTraceID(ctx), deployment.Resolve(ctx)}
		return nil
	})
	s.Require().NoError(err)
	ctx := deployment.WithID(sysContext.WithTraceID(context.Background(), "trace-1"), "deployment-1")

	s.Require().NoError(bus.Publish(ctx, s.event(ctx, testEventName, payloadOne{})))
	s.shutdown(bus)

	s.Equal([2]string{"trace-1", "deployment-1"}, <-received)
}

// Every outcome is checked, not timing: once a call sees the bus closed, every later call of the same
// kind must too, and exactly the subscribers that registered are left.
func (s *EventBusServiceTestSuite) TestPublishRegisterAndStopRunConcurrently() {
	bus := s.newBus(1024, time.Second)
	start := make(chan struct{})
	var registered atomic.Int64
	var wg sync.WaitGroup
	for range 4 {
		wg.Go(func() {
			<-start
			closed := false
			for range 200 {
				err := s.publish(bus, testEventName, payloadOne{})
				if closed || err != nil {
					s.ErrorIs(err, errBusClosed)
					closed = true
				}
			}
		})
	}
	for i := range 4 {
		wg.Go(func() {
			<-start
			closed := false
			for j := range 50 {
				err := bus.Register(categoryOne, fmt.Sprintf("sub-%d-%d", i, j), discard)
				if closed || err != nil {
					s.ErrorIs(err, errBusClosed)
					closed = true
					continue
				}
				registered.Add(1)
			}
		})
	}
	wg.Go(func() {
		<-start
		s.shutdown(bus)
	})

	close(start)
	s.completes(wg.Wait)

	s.ErrorIs(s.publish(bus, testEventName, payloadOne{}), errBusClosed)
	s.Len(s.stats(bus), int(registered.Load()))
}

func (s *EventBusServiceTestSuite) TestDuplicateAndEmptySubscriberIDsAreRejected() {
	bus := s.newBus(8, time.Second)
	defer s.shutdown(bus)
	handler := func(context.Context, Envelope, Payload) error { return nil }
	s.Require().NoError(bus.Register(categoryOne, "same", handler))

	s.ErrorIs(bus.Register(categoryOne, "same", handler), errDuplicateSubscriberID)
	s.ErrorIs(bus.Register(categoryTwo, "same", handler), errDuplicateSubscriberID)
	s.ErrorIs(bus.Register(categoryOne, "", handler), errEmptySubscriberID)
	s.ErrorIs(bus.Register(categoryOne, "nil-handler", nil), errNilHandler)
	s.Len(s.stats(bus), 1)
}

func (s *EventBusServiceTestSuite) TestInvalidEventsAreRejectedAndNothingIsDelivered() {
	bus := s.newBus(8, time.Second)
	rec := subscribe[payloadOne](&s.busSuite, bus, "one", nil)

	s.ErrorIs(bus.Publish(context.Background(), nil), errNilEvent)
	s.ErrorIs(s.publish(bus, "BAD NAME", payloadOne{}), errInvalidEventName)
	s.ErrorIs(s.publish(bus, testEventName), errNoPayload)
	s.ErrorIs(s.publish(bus, testEventName, payloadOne{}, payloadOne{}), errDuplicateCategory)
	s.ErrorIs(s.publish(bus, testEventName, checkedPayload{}), errPayloadIncomplete)
	s.shutdown(bus)

	s.Zero(rec.count())
}

func (s *EventBusServiceTestSuite) TestValidatedPayloadIsDelivered() {
	bus := s.newBus(8, time.Second)
	defer s.shutdown(bus)
	rec := subscribe[checkedPayload](&s.busSuite, bus, "checked", nil)

	s.Require().NoError(s.publish(bus, testEventName, checkedPayload{value: "v"}))

	s.eventually(func() bool { return rec.count() == 1 })
}

func (s *EventBusServiceTestSuite) TestStatsAreOrderedByID() {
	bus := s.newBus(8, time.Second)
	defer s.shutdown(bus)
	subscribe[payloadOne](&s.busSuite, bus, "b", nil)
	subscribe[payloadTwo](&s.busSuite, bus, "a", nil)

	stats := s.stats(bus)

	s.Equal("a", stats[0].ID)
	s.Equal(categoryTwo, stats[0].Category)
	s.Equal("b", stats[1].ID)
}

func (s *EventBusServiceTestSuite) newCatalogBus(strict bool) EventBusInterface {
	return s.newBusWith(Config{
		QueueSize:       8,
		DeliveryTimeout: time.Second,
		Catalog: map[string][]Category{
			"user.created":   {categoryOne},
			"user.signed_in": {categoryOne, categoryTwo},
		},
		RejectUnregistered: strict,
	})
}

func (s *EventBusServiceTestSuite) TestCatalogRejectsARegisteredEventMissingARequiredPayload() {
	bus := s.newCatalogBus(false)
	two := subscribe[payloadTwo](&s.busSuite, bus, "two", nil)

	err := s.publish(bus, "user.created", payloadTwo{})
	s.shutdown(bus)

	s.ErrorIs(err, errMissingPayload)
	s.Contains(err.Error(), `"user.created" needs "test_one"`)
	s.Zero(two.count())
}

func (s *EventBusServiceTestSuite) TestCatalogNamesTheMissingCategoryOfSeveral() {
	bus := s.newCatalogBus(false)
	defer s.shutdown(bus)

	err := s.publish(bus, "user.signed_in", payloadOne{})

	s.ErrorIs(err, errMissingPayload)
	s.Contains(err.Error(), `needs "test_two"`)
	s.NoError(s.publish(bus, "user.signed_in", payloadOne{}, payloadTwo{}))
}

func (s *EventBusServiceTestSuite) TestCatalogAcceptsTheRequiredAndExtraPayloads() {
	bus := s.newCatalogBus(false)
	defer s.shutdown(bus)
	one := subscribe[payloadOne](&s.busSuite, bus, "one", nil)
	two := subscribe[payloadTwo](&s.busSuite, bus, "two", nil)

	s.Require().NoError(s.publish(bus, "user.created", payloadOne{}))
	s.Require().NoError(s.publish(bus, "user.created", payloadOne{}, payloadTwo{}))

	s.eventually(func() bool { return one.count() == 2 && two.count() == 1 })
}

func (s *EventBusServiceTestSuite) TestUnregisteredNameIsAcceptedUnlessTheBusRejectsIt() {
	lenient := s.newCatalogBus(false)
	defer s.shutdown(lenient)
	strict := s.newCatalogBus(true)
	defer s.shutdown(strict)

	s.NoError(s.publish(lenient, "other.happened", payloadOne{}))
	err := s.publish(strict, "other.happened", payloadOne{})

	s.ErrorIs(err, errUnregisteredEvent)
	s.Contains(err.Error(), `"other.happened"`)
	s.NoError(s.publish(strict, "user.created", payloadOne{}))
}

func (s *EventBusServiceTestSuite) TestWithoutACatalogNothingIsChecked() {
	bus := s.newBus(8, time.Second)
	defer s.shutdown(bus)

	s.NoError(s.publish(bus, "anything.at_all", payloadTwo{}))
}

func (s *EventBusServiceTestSuite) TestChangingTheCatalogAfterInitializationHasNoEffect() {
	required := []Category{categoryOne}
	catalog := map[string][]Category{"user.created": required, "user.updated": {categoryOne}}
	bus := s.newBusWith(Config{Catalog: catalog, RejectUnregistered: true})
	defer s.shutdown(bus)

	delete(catalog, "user.updated")
	required[0] = categoryTwo

	s.NoError(s.publish(bus, "user.updated", payloadOne{}))
	s.NoError(s.publish(bus, "user.created", payloadOne{}))
}

func (s *EventBusServiceTestSuite) TestMalformedEventIsReportedBeforeTheCatalog() {
	bus := s.newCatalogBus(true)
	defer s.shutdown(bus)

	s.ErrorIs(s.publish(bus, "BAD NAME", payloadOne{}), errInvalidEventName)
	s.ErrorIs(s.publish(bus, "user.created"), errNoPayload)
}

func sequences(envelopes []Envelope) []uint64 {
	seq := make([]uint64, 0, len(envelopes))
	for _, env := range envelopes {
		seq = append(seq, env.Seq)
	}
	return seq
}

// benchmarkBus returns a bus that is shut down when the benchmark ends.
func benchmarkBus(b *testing.B, cfg Config) EventBusInterface {
	cfg.Source = testSource
	cfg.InstanceID = testInstanceID
	bus, stopper, err := Initialize(cfg)
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(stopper.Stop)
	return bus
}

// discard is a handler that accepts every event.
func discard(context.Context, Envelope, Payload) error { return nil }

func benchmarkPublish(b *testing.B, bus EventBusInterface) {
	ctx := sysContext.WithTraceID(context.Background(), "trace-1")
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		_ = bus.Publish(ctx, NewEvent(ctx, testEventName).With(payloadOne{value: "x"}))
	}
}

func BenchmarkNewEventAndPublishOneSubscriber(b *testing.B) {
	bus := benchmarkBus(b, Config{QueueSize: 1 << 16})
	if err := bus.Register(categoryOne, "bench", discard); err != nil {
		b.Fatal(err)
	}
	benchmarkPublish(b, bus)
}

func BenchmarkNewEventAndPublishOneSubscriberWithCatalog(b *testing.B) {
	bus := benchmarkBus(b, Config{QueueSize: 1 << 16,
		Catalog: map[string][]Category{testEventName: {categoryOne}}, RejectUnregistered: true})
	if err := bus.Register(categoryOne, "bench", discard); err != nil {
		b.Fatal(err)
	}
	benchmarkPublish(b, bus)
}

func BenchmarkNewEventAndPublishNoSubscriber(b *testing.B) {
	benchmarkPublish(b, benchmarkBus(b, Config{}))
}

func BenchmarkNewEventAndPublishFullQueue(b *testing.B) {
	bus := benchmarkBus(b, Config{QueueSize: 1, DeliveryTimeout: time.Minute})
	release := make(chan struct{})
	b.Cleanup(func() { close(release) })
	if err := bus.Register(categoryOne, "stuck", func(context.Context, Envelope, Payload) error {
		<-release
		return nil
	}); err != nil {
		b.Fatal(err)
	}
	benchmarkPublish(b, bus)
}
