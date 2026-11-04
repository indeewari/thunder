// Copyright 2026 The ThunderID Authors
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"context"
	"net/http"
	"sync/atomic"
	"time"

	"github.com/thunder-id/thunderid/internal/system/eventbus"
	"github.com/thunder-id/thunderid/internal/system/log"
)

// rejectionRecorder publishes the event of each mutating call the security layer refuses, within a
// rate limit, and counts the events it suppresses.
type rejectionRecorder struct {
	bus     eventbus.EventBusInterface
	limiter *tokenBucket
	now     func() time.Time
	logger  *log.Logger
	// suppressed counts the refused calls the rate limit kept out of the audit stream.
	suppressed atomic.Uint64
	// lastWarning is when the suppressed count was last reported, in Unix nanoseconds.
	lastWarning atomic.Int64
}

// newRejectionRecorder creates a recorder that publishes on bus and reads the time from now.
func newRejectionRecorder(bus eventbus.EventBusInterface, now func() time.Time) *rejectionRecorder {
	return &rejectionRecorder{
		bus:     bus,
		limiter: newTokenBucket(refusedEventsPerSecond, refusedEventsBurst, now),
		now:     now,
		logger:  log.GetLogger().With(log.String(log.LoggerKeyComponentName, "AuditRejectionRecorder")),
	}
}

// record publishes a refused call as the event of its route with a denied outcome, the target type
// without an ID because the path is the caller's, or as management.request for a path no route
// names. A call over the rate limit is counted instead.
func (r *rejectionRecorder) record(ctx context.Context, req *http.Request, status int) {
	if !r.limiter.allow() {
		r.noteSuppressed(ctx)
		return
	}
	name := EventManagementRequest
	target := Ref{Type: unmappedTargetType}
	action := actionOf(req.Method, status)
	if !isExcluded(req.URL.Path) {
		if route, _, ok := matchManagementRoute(req.Method, req.URL.Path); ok {
			action = route.actionFor(req.Method, status)
			name = route.eventName(action)
			target.Type = route.resource
		}
	}
	evt := eventbus.NewEvent(ctx, name).With(NewPayload(ctx, target, action, outcomeOf(status)))
	eventbus.TryPublish(ctx, r.bus, evt)
}

// noteSuppressed counts a suppressed event and warns with the total at most once per interval.
func (r *rejectionRecorder) noteSuppressed(ctx context.Context) {
	total := r.suppressed.Add(1)
	now := r.now().UnixNano()
	last := r.lastWarning.Load()
	if now-last < int64(suppressedWarningInterval) || !r.lastWarning.CompareAndSwap(last, now) {
		return
	}
	r.logger.Warn(ctx, "Refused calls exceed the audit rate limit, their events are being suppressed",
		log.Any("suppressed", total))
}
