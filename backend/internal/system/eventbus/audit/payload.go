// Copyright 2026 The ThunderID Authors
// SPDX-License-Identifier: Apache-2.0

// Package audit is the audit category of the event bus: the payload that records who did what to
// what and with what outcome, the catalog of audited events, and the middleware that records the
// request context and every mutating management API call.
package audit

import (
	"context"
	"maps"
	"slices"

	"github.com/thunder-id/thunderid/internal/system/eventbus"
)

var (
	_ eventbus.Payload          = Payload{}
	_ eventbus.PayloadValidator = Payload{}
)

// OutcomeSucceeded is the outcome of an attempt that completed.
var OutcomeSucceeded = Outcome{Result: ResultSucceeded}

// OutcomeDenied is the outcome of an attempt a security decision refused, with a stable reason code.
func OutcomeDenied(reason string) Outcome {
	return Outcome{Result: ResultDenied, Reason: reason}
}

// OutcomeFailed is the outcome of an attempt that was allowed but did not complete, with a stable
// reason code.
func OutcomeFailed(reason string) Outcome {
	return Outcome{Result: ResultFailed, Reason: reason}
}

// Payload is the audit view of an event. Build it with NewPayload, so the actor and the client come
// from the request rather than from the call site.
type Payload struct {
	actor      Actor
	onBehalfOf Ref
	subject    Ref
	target     Ref
	action     Action
	outcome    Outcome
	client     Client
	details    map[string]string
}

// NewPayload builds the audit payload of an attempt on target. The actor, the principal it acted
// for and the client are resolved from ctx, which carries the verified security context and what
// ContextMiddleware recorded. Every ID is cut to 128 characters.
func NewPayload(ctx context.Context, target Ref, action Action, outcome Outcome) Payload {
	actor, onBehalfOf := resolveActor(ctx)
	actor.ID = capID(actor.ID)
	onBehalfOf.ID = capID(onBehalfOf.ID)
	target.ID = capID(target.ID)
	client, _ := ctx.Value(clientKey{}).(Client)
	return Payload{
		actor:      actor,
		onBehalfOf: onBehalfOf,
		target:     target,
		action:     action,
		outcome:    outcome,
		client:     client,
	}
}

// Category returns the audit category.
func (Payload) Category() eventbus.Category {
	return CategoryAudit
}

// Validate reports why the payload cannot be published: a target without a type, no action, an
// unknown result, or a denied or failed outcome without a reason code.
func (p Payload) Validate() error {
	if p.target.Type == "" {
		return errMissingTarget
	}
	if p.action == "" {
		return errMissingAction
	}
	switch p.outcome.Result {
	case ResultSucceeded:
		return nil
	case ResultDenied, ResultFailed:
		if p.outcome.Reason == "" {
			return errMissingReason
		}
		if !reasonPattern.MatchString(p.outcome.Reason) {
			return errInvalidReason
		}
		return nil
	default:
		return errUnknownResult
	}
}

// WithSubject names the identity whose activity log the event belongs to.
func (p Payload) WithSubject(subject Ref) Payload {
	subject.ID = capID(subject.ID)
	p.subject = subject
	return p
}

// WithOnBehalfOf names the principal the actor acted for.
func (p Payload) WithOnBehalfOf(principal Ref) Payload {
	principal.ID = capID(principal.ID)
	p.onBehalfOf = principal
	return p
}

// WithClient replaces the client resolved from the request.
func (p Payload) WithClient(client Client) Payload {
	p.client = client
	return p
}

// WithDetails records facts specific to one event. A sink receives only the keys the event's catalog
// entry allows, so a key not listed there is never written.
func (p Payload) WithDetails(details map[string]string) Payload {
	p.details = maps.Clone(details)
	return p
}

// Actor returns the principal that made the attempt.
func (p Payload) Actor() Actor {
	return p.actor
}

// OnBehalfOf returns the principal the actor acted for, the zero Ref when it acted for itself.
func (p Payload) OnBehalfOf() Ref {
	return p.onBehalfOf
}

// Subject returns the identity whose activity log the event belongs to, the zero Ref when none.
func (p Payload) Subject() Ref {
	return p.subject
}

// Target returns what the attempt touched.
func (p Payload) Target() Ref {
	return p.target
}

// Action returns what was attempted.
func (p Payload) Action() Action {
	return p.action
}

// Outcome returns how the attempt ended.
func (p Payload) Outcome() Outcome {
	return p.outcome
}

// Client returns where the request came from.
func (p Payload) Client() Client {
	return p.client
}

// Details returns a copy of the facts specific to the event.
func (p Payload) Details() map[string]string {
	return maps.Clone(p.details)
}

// withAllowedDetails returns the payload with only the detail keys in allowed.
func (p Payload) withAllowedDetails(allowed []string) Payload {
	details := maps.Clone(p.details)
	maps.DeleteFunc(details, func(key, _ string) bool { return !slices.Contains(allowed, key) })
	p.details = details
	return p
}
