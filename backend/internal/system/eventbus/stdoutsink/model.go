// Copyright 2026 The ThunderID Authors
// SPDX-License-Identifier: Apache-2.0

package stdoutsink

// line is the JSON shape of one audit line after the type marker, which the sink writes first.
type line struct {
	SchemaVersion int               `json:"schema_version"`
	ID            string            `json:"id"`
	Time          string            `json:"time"`
	Event         string            `json:"event"`
	TraceID       string            `json:"trace_id"`
	TraceParent   string            `json:"traceparent,omitempty"`
	DeploymentID  string            `json:"deployment_id"`
	Source        string            `json:"source"`
	InstanceID    string            `json:"instance_id"`
	BootID        string            `json:"boot_id"`
	Seq           uint64            `json:"seq"`
	Actor         refLine           `json:"actor"`
	OnBehalfOf    *refLine          `json:"on_behalf_of,omitempty"`
	Subject       *refLine          `json:"subject,omitempty"`
	Target        refLine           `json:"target"`
	Action        string            `json:"action"`
	Outcome       outcomeLine       `json:"outcome"`
	Client        *clientLine       `json:"client,omitempty"`
	Details       map[string]string `json:"details,omitempty"`
}

// refLine is an actor, a subject or a target: a type and, where one exists, an ID.
type refLine struct {
	Type string `json:"type"`
	ID   string `json:"id,omitempty"`
}

// outcomeLine is how the attempt ended.
type outcomeLine struct {
	Result string `json:"result"`
	Reason string `json:"reason,omitempty"`
}

// clientLine is where the request came from.
type clientLine struct {
	Address   string `json:"address,omitempty"`
	UserAgent string `json:"user_agent,omitempty"`
}
