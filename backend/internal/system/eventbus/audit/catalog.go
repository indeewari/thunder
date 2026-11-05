// Copyright 2026 The ThunderID Authors
// SPDX-License-Identifier: Apache-2.0

package audit

import "github.com/thunder-id/thunderid/internal/system/eventbus"

// Audited event names. A publisher uses these constants, and the catalog lists what each may carry.
// The management middleware also publishes the names the route table derives, <resource>.<action>.
const (
	// EventManagementRequest names a mutating management API call on a path the route table does not
	// name, so that no such call goes unrecorded.
	EventManagementRequest = "management.request"

	// EventUserCreate names an attempt to create a user.
	EventUserCreate = "user.create"
	// EventUserUpdate names an attempt to change a user.
	EventUserUpdate = "user.update"
	// EventUserDelete names an attempt to delete a user.
	EventUserDelete = "user.delete"
)

// TargetTypeUser is the target type of an event about a user.
const TargetTypeUser = "user"

// catalogEntry describes one audited event.
type catalogEntry struct {
	// details are the keys the event may carry in its details. Any other key is never written.
	details []string
}

// catalog lists every audited event, so what is audited can be reviewed in one place.
var catalog = buildCatalog()

// Catalog returns the event bus catalog of the audited events: each must carry an audit payload. The
// map is a copy.
func Catalog() map[string][]eventbus.Category {
	entries := make(map[string][]eventbus.Category, len(catalog))
	for name := range catalog {
		entries[name] = []eventbus.Category{CategoryAudit}
	}
	return entries
}

// buildCatalog lists the fixed events and every event the route table derives.
func buildCatalog() map[string]catalogEntry {
	entries := map[string]catalogEntry{EventManagementRequest: {}}
	for _, route := range managementRoutes {
		for _, action := range route.actions() {
			entries[route.eventName(action)] = catalogEntry{}
		}
	}
	return entries
}

// allowedDetails returns the detail keys an event of the given name may carry.
func allowedDetails(name string) []string {
	return catalog[name].details
}
