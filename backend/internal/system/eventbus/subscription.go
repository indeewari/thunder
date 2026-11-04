// Copyright 2026 The ThunderID Authors
// SPDX-License-Identifier: Apache-2.0

package eventbus

import (
	"context"
	"errors"
	"sync/atomic"
	"time"

	sysContext "github.com/thunder-id/thunderid/internal/system/context"
	"github.com/thunder-id/thunderid/internal/system/deployment"
	"github.com/thunder-id/thunderid/internal/system/log"
)

// subscription is one subscriber with its queue and counters.
type subscription struct {
	id       string
	category Category
	handler  Handler
	queue    chan delivery
	logger   *log.Logger

	delivered atomic.Uint64
	dropped   atomic.Uint64
	failed    atomic.Uint64
	timedOut  atomic.Uint64
	panicked  atomic.Uint64
	abandoned atomic.Uint64

	dropLog    logLimiter
	failureLog logLimiter
	timeoutLog logLimiter
	panicLog   logLimiter
}

// run delivers queued events one at a time until the queue is closed, dropping them once canceled.
func (s *subscription) run(bus *eventBusService) {
	defer bus.wg.Done()
	for d := range s.queue {
		if bus.ctx.Err() != nil {
			s.abandon()
			continue
		}
		s.deliver(bus.ctx, bus.timeout, d)
	}
}

// deliver calls the handler with a deadline and counts the outcome. A panic or error never stops the worker.
func (s *subscription) deliver(busCtx context.Context, timeout time.Duration, d delivery) {
	ctx := deployment.WithID(sysContext.WithTraceID(busCtx, d.env.TraceID), d.env.DeploymentID)
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	defer func() {
		if r := recover(); r != nil {
			s.panicked.Add(1)
			if s.panicLog.allow() {
				s.logger.Error(ctx, "Subscriber panicked while handling an event",
					eventFields(d.env, log.Any("panic", r))...)
			}
		}
	}()

	err := s.handler(ctx, d.env, d.payload)
	switch {
	case err == nil:
		s.delivered.Add(1)
	case errors.Is(err, context.DeadlineExceeded):
		s.timedOut.Add(1)
		if s.timeoutLog.allow() {
			s.logger.Warn(ctx, "Subscriber timed out handling an event", eventFields(d.env)...)
		}
	default:
		s.failed.Add(1)
		if s.failureLog.allow() {
			s.logger.Error(ctx, "Subscriber failed to handle an event", eventFields(d.env, log.Error(err))...)
		}
	}
}

// noteDrop counts a dropped event and warns at most once per interval.
func (s *subscription) noteDrop(ctx context.Context) {
	total := s.dropped.Add(1)
	if !s.dropLog.allow() {
		return
	}
	s.logger.Warn(ctx, "Subscriber queue is full, events are being dropped", log.Any("dropped", total))
}

// abandon counts an event the bus stopped before delivering.
func (s *subscription) abandon() {
	s.dropped.Add(1)
	s.abandoned.Add(1)
}

// abandonQueued drops what is left on the closed queue.
func (s *subscription) abandonQueued() {
	for range s.queue {
		s.abandon()
	}
}

// reportAbandoned logs how many events the bus stopped before delivering, if any.
func (s *subscription) reportAbandoned() {
	if abandoned := s.abandoned.Load(); abandoned > 0 {
		s.logger.Warn(context.Background(), "Event bus stopped before delivering queued events",
			log.Any("abandoned", abandoned))
	}
}

// stats returns a snapshot of the counters.
func (s *subscription) stats() SubscriberStats {
	return SubscriberStats{
		ID:        s.id,
		Category:  s.category,
		Delivered: s.delivered.Load(),
		Dropped:   s.dropped.Load(),
		Failed:    s.failed.Load(),
		TimedOut:  s.timedOut.Load(),
		Panicked:  s.panicked.Load(),
	}
}

// logLimiter lets one log line through per logInterval.
type logLimiter struct {
	last atomic.Int64
}

// allow reports whether a line may be logged now and, if so, starts a new interval.
func (l *logLimiter) allow() bool {
	now := time.Now().UnixNano()
	last := l.last.Load()
	return now-last >= int64(logInterval) && l.last.CompareAndSwap(last, now)
}

// eventFields returns the log fields that identify an event, followed by extra.
func eventFields(env Envelope, extra ...log.Field) []log.Field {
	return append([]log.Field{log.String("eventID", env.ID), log.String("event", env.Name)}, extra...)
}
