// Copyright 2026 The ThunderID Authors
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"context"
	"net"
	"net/http"
	"strconv"
	"strings"

	"github.com/thunder-id/thunderid/internal/system/eventbus"
)

// clientKey is the context key of the request's Client.
type clientKey struct{}

// withClient returns ctx carrying where r came from.
func withClient(ctx context.Context, r *http.Request) context.Context {
	address, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		address = r.RemoteAddr
	}
	userAgent := r.UserAgent()
	if runes := []rune(userAgent); len(runes) > maxUserAgentLength {
		userAgent = string(runes[:maxUserAgentLength])
	}
	return context.WithValue(ctx, clientKey{}, Client{Address: address, UserAgent: userAgent})
}

// managementEvent builds the event of a mutating management call answered with status. A call on a
// route the table does not name is published under the generic name.
func managementEvent(ctx context.Context, r *http.Request, status int) *eventbus.Event {
	route, id, ok := matchManagementRoute(r.Method, r.URL.Path)
	if !ok {
		return eventbus.NewEvent(ctx, EventManagementRequest).
			With(NewPayload(ctx, targetOf(r), actionOf(r.Method, status), outcomeOf(status)))
	}
	action := route.actionFor(r.Method, status)
	return eventbus.NewEvent(ctx, route.eventName(action)).
		With(NewPayload(ctx, Ref{Type: route.resource, ID: id}, action, outcomeOf(status)))
}

// actionOf maps a mutating call to an action. A 201 means the call created its target, whatever the
// method.
func actionOf(method string, status int) Action {
	if status == http.StatusCreated {
		return ActionCreate
	}
	switch method {
	case http.MethodPost:
		return ActionCreate
	case http.MethodDelete:
		return ActionDelete
	default:
		return ActionUpdate
	}
}

// outcomeOf maps a response status to an outcome with a stable reason code: 401 and 403 are denied,
// any other error failed.
func outcomeOf(status int) Outcome {
	switch {
	case status < http.StatusBadRequest:
		return OutcomeSucceeded
	case status == http.StatusUnauthorized:
		return OutcomeDenied(reasonUnauthorized)
	case status == http.StatusForbidden:
		return OutcomeDenied(reasonForbidden)
	case status == http.StatusBadRequest:
		return OutcomeFailed(reasonInvalidRequest)
	case status == http.StatusNotFound:
		return OutcomeFailed(reasonNotFound)
	case status == http.StatusConflict:
		return OutcomeFailed(reasonConflict)
	case status >= http.StatusInternalServerError:
		return OutcomeFailed(reasonServerError)
	default:
		return OutcomeFailed(statusReasonPrefix + strconv.Itoa(status))
	}
}

// targetOf derives the target of a call on a route the table does not name from the matched route:
// the first path segment is the type, and the value of the first wildcard, when the route has one, is
// the ID.
func targetOf(r *http.Request) Ref {
	path := routePath(r.Pattern)
	resourceType, _, _ := strings.Cut(strings.TrimPrefix(path, "/"), "/")
	target := Ref{Type: resourceType}
	if match := routeWildcardPattern.FindStringSubmatch(path); match != nil {
		target.ID = r.PathValue(match[1])
	}
	return target
}

// routePath returns the path of a route pattern, without its method and host.
func routePath(pattern string) string {
	if _, rest, found := strings.Cut(pattern, " "); found {
		pattern = rest
	}
	if index := strings.Index(pattern, "/"); index > 0 {
		return pattern[index:]
	}
	return pattern
}

// capID cuts an ID to its first maxIDLength characters.
func capID(id string) string {
	if runes := []rune(id); len(runes) > maxIDLength {
		return string(runes[:maxIDLength])
	}
	return id
}
