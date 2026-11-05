// Copyright 2026 The ThunderID Authors
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"net/http"
	"slices"
	"strings"
)

// managementRoute names the resource a family of management routes changes. A call it matches is
// published as <resource>.<action>, the action attempted whatever the outcome, with the resource as
// the target type.
type managementRoute struct {
	// method is the method the entry matches. Empty matches every mutating method.
	method string
	// path is a glob over the request path: "*" is one segment, "{id}" is one segment recorded as the
	// target ID, and a final "**" is any remainder. The ID is the changed resource's own; a resource
	// that has none, such as the members of a group, is identified by its parent.
	path string
	// resource is the target type and the first segment of the event name.
	resource string
	// action, when set, is the action of every call the entry matches, for an operation that is not a
	// create, an update or a delete of the resource.
	action Action
	// alwaysRecorded records the call even when a service published its own audit event during it.
	alwaysRecorded bool
}

// excludedRoutes are the routes the management middleware never records: protocol, sign-in,
// discovery, health and frontend routes, self-service routes, and mutating methods that change
// nothing. They share the mux with the management APIs but are not administration.
var excludedRoutes = []string{
	"/oauth2/**",
	"/ou/*/oauth2/**",
	"/flow/**",
	"/.well-known/**",
	"/auth/**",
	"/register/**",
	"/access/**",
	"/openid4vp/request",
	"/openid4vp/response",
	"/openid4vp/initiate",
	"/openid4vp/status/**",
	"/openid4vci/offer",
	"/openid4vci/credential-offer/**",
	"/openid4vci/nonce",
	"/openid4vci/credential",
	"/design/resolve/**",
	"/health/**",
	"/gate/**",
	"/console/**",
	"/error/**",
	"/mcp/**",
	"/export/**",
	"/cimd/preview",
	"/users/me/**",
	"/scim/v2/Me",
	"/scim/v2/Users/.search",
	"/scim/v2/Groups/.search",
}

// managementRoutes is the table of audited management route families, the review reference for what
// is audited under which name. The first entry that matches wins.
var managementRoutes = []managementRoute{
	{http.MethodPost, "/organization-units", "organization_unit", "", false},
	{"", "/organization-units/tree/**", "organization_unit", "", false},
	{"", "/organization-units/{id}", "organization_unit", "", false},

	{http.MethodPost, "/users", "user", "", false},
	{http.MethodPost, "/users/tree/**", "user", "", false},
	{http.MethodPost, "/users/{id}/update-credentials", "user_credential", ActionUpdate, false},
	{"", "/users/*/sharing-policies/{id}", "user_sharing_policy", "", false},
	{http.MethodPost, "/users/*/sharing-policies", "user_sharing_policy", "", false},
	{"", "/users/{id}", "user", "", false},
	{http.MethodPost, "/scim/v2/Users", "user", "", false},
	{"", "/scim/v2/Users/{id}", "user", "", false},

	{http.MethodPost, "/groups", "group", "", false},
	{http.MethodPost, "/groups/tree/**", "group", "", false},
	{http.MethodPost, "/groups/{id}/members/add", "group_membership", ActionAdd, false},
	{http.MethodPost, "/groups/{id}/members/remove", "group_membership", ActionRemove, false},
	{"", "/groups/{id}", "group", "", false},
	{http.MethodPost, "/scim/v2/Groups", "group", "", false},
	{"", "/scim/v2/Groups/{id}", "group", "", false},

	{http.MethodPost, "/agents", "agent", "", false},
	{"", "/agents/{id}", "agent", "", false},
	{http.MethodPost, "/user-types", "user_type", "", false},
	{"", "/user-types/{id}", "user_type", "", false},
	{http.MethodPost, "/agent-types", "agent_type", "", false},
	{"", "/agent-types/{id}", "agent_type", "", false},
	{http.MethodPost, "/notification-templates/*/templates", "notification_template", "", false},
	{"", "/notification-templates/*/templates/{id}", "notification_template", "", false},
	{http.MethodPost, "/projects", "project", "", false},
	{"", "/projects/{id}", "project", "", false},

	{http.MethodPost, "/variables", "variable", "", false},
	{"", "/variables/{id}", "variable", "", false},
	{http.MethodPost, "/secrets", "secret", "", false},
	{"", "/secrets/{id}", "secret", "", false},
	{http.MethodPost, "/import", "configuration", ActionImport, true},
	{http.MethodPost, "/import/delete", "configuration", ActionDelete, true},

	{http.MethodPost, "/applications", "application", "", false},
	{http.MethodPost, "/applications/*/sharing-policies", "application_sharing_policy", "", false},
	{"", "/applications/*/sharing-policies/{id}", "application_sharing_policy", "", false},
	{"", "/applications/{id}", "application", "", false},

	{http.MethodPost, "/flows", "flow", "", false},
	{http.MethodPost, "/flows/{id}/restore", "flow", ActionRestore, false},
	{"", "/flows/{id}/variables", "flow_variables", "", false},
	{http.MethodPost, "/flows/*/sharing-policies", "flow_sharing_policy", "", false},
	{"", "/flows/*/sharing-policies/{id}", "flow_sharing_policy", "", false},
	{"", "/flows/{id}", "flow", "", false},

	{http.MethodPost, "/roles", "role", "", false},
	{http.MethodPost, "/roles/{id}/assignments/add", "role_assignment", ActionAdd, false},
	{http.MethodPost, "/roles/{id}/assignments/remove", "role_assignment", ActionRemove, false},
	{http.MethodPost, "/roles/*/sharing-policies", "role_sharing_policy", "", false},
	{"", "/roles/*/sharing-policies/{id}", "role_sharing_policy", "", false},
	{"", "/roles/{id}", "role", "", false},

	{http.MethodPost, "/resource-servers", "resource_server", "", false},
	{http.MethodPost, "/resource-servers/*/resources", "resource", "", false},
	{http.MethodPost, "/resource-servers/*/resources/*/actions", "resource_action", "", false},
	{"", "/resource-servers/*/resources/*/actions/{id}", "resource_action", "", false},
	{"", "/resource-servers/*/resources/{id}", "resource", "", false},
	{http.MethodPost, "/resource-servers/*/actions", "resource_action", "", false},
	{"", "/resource-servers/*/actions/{id}", "resource_action", "", false},
	{"", "/resource-servers/{id}", "resource_server", "", false},
	{http.MethodPost, "/authorization-detail-types", "authorization_detail_type", "", false},
	{"", "/authorization-detail-types/{id}", "authorization_detail_type", "", false},

	{http.MethodPost, "/connections/*", "connection", "", false},
	{http.MethodPost, "/connections/*/*/sharing-policies", "connection_sharing_policy", "", false},
	{"", "/connections/*/*/sharing-policies/{id}", "connection_sharing_policy", "", false},
	{"", "/connections/*/{id}", "connection", "", false},

	{http.MethodPost, "/design/themes", "theme", "", false},
	{"", "/design/themes/{id}", "theme", "", false},
	{http.MethodPost, "/design/layouts", "layout", "", false},
	{"", "/design/layouts/{id}", "layout", "", false},
	{"", "/i18n/languages/{id}/translations", "translation", "", false},
	{"", "/i18n/languages/*/translations/ns/*/keys/{id}", "translation", "", false},
	{"", "/server-config/{id}", "server_config", "", false},
	{http.MethodPost, "/openid4vci/credential-configurations", "credential_configuration", "", false},
	{"", "/openid4vci/credential-configurations/{id}", "credential_configuration", "", false},
	{http.MethodPost, "/openid4vp/presentation-definitions", "presentation_definition", "", false},
	{"", "/openid4vp/presentation-definitions/{id}", "presentation_definition", "", false},

	{http.MethodPost, "/gateways", "gateway", "", false},
	{http.MethodPost, "/gateways/{id}/apply", "gateway", ActionApply, false},
	{http.MethodPost, "/gateways/{id}/revert", "gateway", ActionRevert, false},
	{http.MethodPost, "/gateways/*/variables", "gateway_variable", "", false},
	{"", "/gateways/*/variables/{id}", "gateway_variable", "", false},
	{http.MethodPost, "/gateways/*/secrets", "gateway_secret", "", false},
	{"", "/gateways/*/secrets/{id}", "gateway_secret", "", false},
	{"", "/gateways/{id}", "gateway", "", false},
	{http.MethodPost, "/configuration-versions", "configuration_version", "", false},
}

// actions returns every action a call the entry matches can be published with.
func (r managementRoute) actions() []Action {
	if r.action != "" {
		return []Action{r.action}
	}
	if r.method == "" {
		return []Action{ActionCreate, ActionUpdate, ActionDelete}
	}
	return slices.Compact([]Action{ActionCreate, actionOf(r.method, http.StatusOK)})
}

// actionFor returns the action of a call the entry matched, answered with status.
func (r managementRoute) actionFor(method string, status int) Action {
	if r.action != "" {
		return r.action
	}
	return actionOf(method, status)
}

// eventName returns the name of the event of a call the entry matched.
func (r managementRoute) eventName(action Action) string {
	return r.resource + "." + string(action)
}

// matchManagementRoute returns the table entry for a mutating call and the target ID in its path.
func matchManagementRoute(method, path string) (managementRoute, string, bool) {
	for _, route := range managementRoutes {
		if route.method != "" && route.method != method {
			continue
		}
		if id, ok := matchGlob(route.path, path); ok {
			return route, id, true
		}
	}
	return managementRoute{}, "", false
}

// isAlwaysRecorded reports whether a mutating call's route is recorded even when a service published
// its own audit event during the call.
func isAlwaysRecorded(method, path string) bool {
	route, _, ok := matchManagementRoute(method, path)
	return ok && route.alwaysRecorded
}

// isExcluded reports whether a request path is outside the audited management APIs.
func isExcluded(path string) bool {
	for _, glob := range excludedRoutes {
		if _, ok := matchGlob(glob, path); ok {
			return true
		}
	}
	return false
}

// matchGlob reports whether path matches glob, and returns the segment at the glob's ID token. A
// wildcard never matches an empty segment.
func matchGlob(glob, path string) (string, bool) {
	globSegments := strings.Split(strings.TrimPrefix(glob, "/"), "/")
	pathSegments := strings.Split(strings.TrimPrefix(path, "/"), "/")
	id := ""
	for i, token := range globSegments {
		if token == globAnyRemainder {
			return id, true
		}
		if i >= len(pathSegments) {
			return "", false
		}
		segment := pathSegments[i]
		switch token {
		case globAnySegment, globIDSegment:
			if segment == "" {
				return "", false
			}
			if token == globIDSegment {
				id = segment
			}
		default:
			if segment != token {
				return "", false
			}
		}
	}
	if len(pathSegments) != len(globSegments) {
		return "", false
	}
	return id, true
}
