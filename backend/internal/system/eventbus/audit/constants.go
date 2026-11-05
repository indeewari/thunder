// Copyright 2026 The ThunderID Authors
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"regexp"
	"time"

	"github.com/thunder-id/thunderid/internal/system/eventbus"
)

// CategoryAudit is the category of audit payloads: who did what to what, and with what outcome.
const CategoryAudit eventbus.Category = "audit"

// Action is what an actor attempted. The set is open, so a new action needs no change here.
type Action string

const (
	// ActionCreate creates a resource.
	ActionCreate Action = "create"
	// ActionUpdate changes a resource.
	ActionUpdate Action = "update"
	// ActionDelete removes a resource.
	ActionDelete Action = "delete"
	// ActionAdd adds members or assignments to a resource.
	ActionAdd Action = "add"
	// ActionRemove removes members or assignments from a resource.
	ActionRemove Action = "remove"
	// ActionRestore returns a resource to an earlier version.
	ActionRestore Action = "restore"
	// ActionImport applies a configuration document.
	ActionImport Action = "import"
	// ActionApply deploys configuration to a gateway.
	ActionApply Action = "apply"
	// ActionRevert returns a gateway to its previous configuration.
	ActionRevert Action = "revert"
)

// ActorType is the kind of principal that acted. The set is open.
type ActorType string

const (
	// ActorTypeUser is a person.
	ActorTypeUser ActorType = "user"
	// ActorTypeApplication is an OAuth client acting for itself.
	ActorTypeApplication ActorType = "application"
	// ActorTypeAgent is an AI agent.
	ActorTypeAgent ActorType = "agent"
	// ActorTypeSystem is the deployment itself, such as its management API key.
	ActorTypeSystem ActorType = "system"
	// ActorTypeAnonymous is a caller that presented no verified identity.
	ActorTypeAnonymous ActorType = "anonymous"
)

// Result is how an attempt ended.
type Result string

const (
	// ResultSucceeded is an attempt that completed.
	ResultSucceeded Result = "succeeded"
	// ResultDenied is an attempt a security decision refused.
	ResultDenied Result = "denied"
	// ResultFailed is an attempt that was allowed but did not complete.
	ResultFailed Result = "failed"
)

// ReasonForbidden is the reason of an attempt denied because the caller lacks the permission for it.
const ReasonForbidden = "forbidden"

const (
	// The token claims the actor is read from. They are declared here rather than imported from the
	// OAuth package, which the Control Plane must not link.
	claimAct     = "act"
	claimSub     = "sub"
	claimSubType = "sub_type"

	// maxUserAgentLength is the most characters of a user agent an event records.
	maxUserAgentLength = 256
	// maxIDLength is the most characters of an actor, subject or target ID an event records.
	maxIDLength = 128

	// refusedEventsPerSecond and refusedEventsBurst limit the events of refused calls. The audit queue
	// holds 1,024 events, so a burst of 100 cannot fill it alone.
	refusedEventsPerSecond = 20
	refusedEventsBurst     = 100
	// suppressedWarningInterval is the least time between two warnings about suppressed events.
	suppressedWarningInterval = 30 * time.Second

	// Reason codes of an outcome taken from a response status.
	reasonUnauthorized   = "unauthorized"
	reasonInvalidRequest = "invalid_request"
	reasonNotFound       = "not_found"
	reasonConflict       = "conflict"
	reasonServerError    = "server_error"
	// statusReasonPrefix starts the reason code of any other error status, as in http_422.
	statusReasonPrefix = "http_"

	// unmappedTargetType is the target type of a refused call on a path no route family names. The
	// path of a refused call is chosen by the caller, so it never becomes a target type.
	unmappedTargetType = "unmapped"

	// Tokens of a route glob: one segment, one segment recorded as the target ID, and any remainder.
	globAnySegment   = "*"
	globIDSegment    = "{id}"
	globAnyRemainder = "**"
)

var (
	// reasonPattern is the grammar of an outcome reason: a stable lowercase code, never free text.
	reasonPattern = regexp.MustCompile(`^[a-z][a-z0-9_]{0,63}$`)

	// routeWildcardPattern finds the wildcard names of a route pattern, such as {id} or {path...}.
	routeWildcardPattern = regexp.MustCompile(`\{([A-Za-z_][A-Za-z0-9_]*)(?:\.\.\.)?\}`)
)
