// Copyright 2026 The ThunderID Authors
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"net/http"
	"time"

	"github.com/thunder-id/thunderid/internal/system/constants"
	"github.com/thunder-id/thunderid/internal/system/eventbus"
	"github.com/thunder-id/thunderid/internal/system/security"
	"github.com/thunder-id/thunderid/internal/system/utils"
)

// ContextMiddleware records where the request came from and its W3C trace context on the request
// context, so a payload built below it resolves them, and a marker that building a payload sets. The
// client address is the TCP peer address: forwarded headers are caller controlled and are never read.
func ContextMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := withClient(r.Context(), r)
		ctx = eventbus.WithTraceParent(ctx, r.Header.Get(constants.TraceParentHeaderName))
		ctx = withPayloadMarker(ctx)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// ManagementMiddleware publishes an event on bus for every mutating management API call that reaches
// the routes behind it, named by the route table, or management.request for a path the table does not
// name. A call during which a service built an audit payload already has its event, so it publishes
// none for it unless its route is always recorded. It wraps the mux inside the security middleware:
// the mux tells it whether a route matched, and the security middleware puts the actor on the request
// context.
func ManagementMiddleware(bus eventbus.EventBusInterface) (func(http.Handler) http.Handler, error) {
	if bus == nil {
		return nil, errNilBus
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !utils.IsMutatingMethod(r.Method) {
				next.ServeHTTP(w, r)
				return
			}
			recorder := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
			next.ServeHTTP(recorder, r)

			// Read only now: the mux sets the pattern while it serves the request. No pattern means
			// no route matched.
			if r.Pattern == "" || isExcluded(r.URL.Path) ||
				(isPayloadBuilt(r.Context()) && !isAlwaysRecorded(r.Method, r.URL.Path)) {
				return
			}
			ctx := r.Context()
			eventbus.TryPublish(ctx, bus, managementEvent(ctx, r, recorder.status))
		})
	}, nil
}

// RejectionHook returns the security layer hook that publishes, on bus, the event of the route of a
// mutating call the layer refused, with a denied outcome. The events are rate limited, so a scanner
// cannot crowd real events out of the audit queue.
func RejectionHook(bus eventbus.EventBusInterface) (security.RejectionHook, error) {
	if bus == nil {
		return nil, errNilBus
	}
	return newRejectionRecorder(bus, time.Now).record, nil
}

// statusRecorder remembers the status a handler answered with.
type statusRecorder struct {
	http.ResponseWriter
	status      int
	wroteHeader bool
}

// WriteHeader records the first status written and passes it on.
func (r *statusRecorder) WriteHeader(status int) {
	if !r.wroteHeader {
		r.status = status
		r.wroteHeader = true
	}
	r.ResponseWriter.WriteHeader(status)
}

// Write marks the status as sent and passes the body on.
func (r *statusRecorder) Write(body []byte) (int, error) {
	r.wroteHeader = true
	return r.ResponseWriter.Write(body)
}

// Flush marks the status as sent and flushes the wrapped writer when it can, so a streaming handler
// behind the middleware still streams.
func (r *statusRecorder) Flush() {
	r.wroteHeader = true
	if flusher, ok := r.ResponseWriter.(http.Flusher); ok {
		flusher.Flush()
	}
}

// Unwrap returns the wrapped ResponseWriter, so http.ResponseController reaches the connection.
func (r *statusRecorder) Unwrap() http.ResponseWriter {
	return r.ResponseWriter
}
