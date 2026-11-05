// Copyright 2026 The ThunderID Authors
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"context"
	"net/http"
	"testing"

	"github.com/stretchr/testify/suite"

	"github.com/thunder-id/thunderid/internal/system/eventbus"
	"github.com/thunder-id/thunderid/internal/system/utils"
)

type RoutesTestSuite struct {
	suite.Suite
}

func TestRoutesTestSuite(t *testing.T) {
	suite.Run(t, new(RoutesTestSuite))
}

// Every name the table can derive is in the catalog, so a bus that rejects unregistered names accepts
// every event the middleware publishes.
func (s *RoutesTestSuite) TestEveryDerivedNameIsInTheCatalog() {
	catalog := Catalog()
	for _, route := range managementRoutes {
		actions := route.actions()
		s.NotEmpty(actions, route.path)
		for _, action := range actions {
			s.Equal(route.resource+"."+string(action), route.eventName(action))
			s.Contains(catalog, route.eventName(action), route.path)
		}
	}
	s.Contains(catalog, EventManagementRequest)
}

// Publishing each catalog name on a bus built like the binaries' proves it follows the name grammar.
func (s *RoutesTestSuite) TestEveryCatalogNameFollowsTheEventNameGrammar() {
	bus, events := newAuditBus(s.T())
	ctx := context.Background()

	for name := range Catalog() {
		s.NoError(bus.Publish(ctx, eventbus.NewEvent(ctx, name).
			With(NewPayload(ctx, Ref{Type: "test"}, ActionUpdate, OutcomeSucceeded))), name)
		s.Equal(name, awaitEvent(s.T(), events).env.Name)
	}
}

func (s *RoutesTestSuite) TestATableEntryHasAResourceAndAMutatingMethod() {
	for _, route := range managementRoutes {
		s.NotEmpty(route.resource, route.path)
		s.True(route.method == "" || utils.IsMutatingMethod(route.method), route.path)
	}
}

func (s *RoutesTestSuite) TestMatchManagementRoute() {
	for _, tc := range []struct {
		method, path string
		resource     string
		id           string
		action       Action
	}{
		{http.MethodPost, "/organization-units", "organization_unit", "", ActionCreate},
		{http.MethodPut, "/organization-units/ou1", "organization_unit", "ou1", ActionUpdate},
		{http.MethodDelete, "/organization-units/tree/a/b", "organization_unit", "", ActionDelete},
		{http.MethodPost, "/users", "user", "", ActionCreate},
		{http.MethodPost, "/users/tree/a/b", "user", "", ActionCreate},
		{http.MethodPut, "/users/u1", "user", "u1", ActionUpdate},
		{http.MethodDelete, "/users/u1", "user", "u1", ActionDelete},
		{http.MethodPost, "/users/u1/update-credentials", "user_credential", "u1", ActionUpdate},
		{http.MethodPost, "/users/u1/sharing-policies", "user_sharing_policy", "", ActionCreate},
		{http.MethodPut, "/users/u1/sharing-policies/p1", "user_sharing_policy", "p1", ActionUpdate},
		{http.MethodPost, "/groups/tree/a", "group", "", ActionCreate},
		{http.MethodPut, "/groups/g1", "group", "g1", ActionUpdate},
		{http.MethodPost, "/groups/g1/members/add", "group_membership", "g1", ActionAdd},
		{http.MethodPost, "/groups/g1/members/remove", "group_membership", "g1", ActionRemove},
		{http.MethodPut, "/agents/a1", "agent", "a1", ActionUpdate},
		{http.MethodPost, "/user-types", "user_type", "", ActionCreate},
		{http.MethodDelete, "/agent-types/t1", "agent_type", "t1", ActionDelete},
		{http.MethodPost, "/notification-templates/email/templates", "notification_template", "", ActionCreate},
		{http.MethodPut, "/notification-templates/email/templates/t1", "notification_template", "t1",
			ActionUpdate},
		{http.MethodDelete, "/projects/p1", "project", "p1", ActionDelete},
		{http.MethodPut, "/variables/API_URL", "variable", "API_URL", ActionUpdate},
		{http.MethodPost, "/secrets", "secret", "", ActionCreate},
		{http.MethodPost, "/import", "configuration", "", ActionImport},
		{http.MethodPost, "/import/delete", "configuration", "", ActionDelete},
		{http.MethodPost, "/scim/v2/Users", "user", "", ActionCreate},
		{http.MethodPatch, "/scim/v2/Groups/g1", "group", "g1", ActionUpdate},
		{http.MethodPut, "/applications/app1", "application", "app1", ActionUpdate},
		{http.MethodDelete, "/applications/app1/sharing-policies/p1", "application_sharing_policy", "p1",
			ActionDelete},
		{http.MethodPost, "/flows", "flow", "", ActionCreate},
		{http.MethodPost, "/flows/f1/restore", "flow", "f1", ActionRestore},
		{http.MethodPut, "/flows/f1/variables", "flow_variables", "f1", ActionUpdate},
		{http.MethodPost, "/flows/f1/sharing-policies", "flow_sharing_policy", "", ActionCreate},
		{http.MethodPost, "/roles/r1/assignments/add", "role_assignment", "r1", ActionAdd},
		{http.MethodPost, "/roles/r1/assignments/remove", "role_assignment", "r1", ActionRemove},
		{http.MethodPut, "/roles/r1/sharing-policies/p1", "role_sharing_policy", "p1", ActionUpdate},
		{http.MethodDelete, "/roles/r1", "role", "r1", ActionDelete},
		{http.MethodPost, "/resource-servers", "resource_server", "", ActionCreate},
		{http.MethodPut, "/resource-servers/rs1", "resource_server", "rs1", ActionUpdate},
		{http.MethodPost, "/resource-servers/rs1/resources", "resource", "", ActionCreate},
		{http.MethodPut, "/resource-servers/rs1/resources/r1", "resource", "r1", ActionUpdate},
		{http.MethodPost, "/resource-servers/rs1/actions", "resource_action", "", ActionCreate},
		{http.MethodDelete, "/resource-servers/rs1/resources/r1/actions/a1", "resource_action", "a1",
			ActionDelete},
		{http.MethodPost, "/authorization-detail-types", "authorization_detail_type", "", ActionCreate},
		{http.MethodPost, "/connections/google", "connection", "", ActionCreate},
		{http.MethodPut, "/connections/email-smtp/c1", "connection", "c1", ActionUpdate},
		{http.MethodPost, "/connections/google/c1/sharing-policies", "connection_sharing_policy", "",
			ActionCreate},
		{http.MethodPut, "/design/themes/th1", "theme", "th1", ActionUpdate},
		{http.MethodPost, "/design/layouts", "layout", "", ActionCreate},
		{http.MethodPost, "/i18n/languages/en-US/translations", "translation", "en-US", ActionCreate},
		{http.MethodDelete, "/i18n/languages/en-US/translations/ns/common/keys/title", "translation", "title",
			ActionDelete},
		{http.MethodPut, "/server-config/cors", "server_config", "cors", ActionUpdate},
		{http.MethodPost, "/openid4vci/credential-configurations", "credential_configuration", "", ActionCreate},
		{http.MethodDelete, "/openid4vp/presentation-definitions/d1", "presentation_definition", "d1",
			ActionDelete},
		{http.MethodPost, "/gateways", "gateway", "", ActionCreate},
		{http.MethodPost, "/gateways/gw1/apply", "gateway", "gw1", ActionApply},
		{http.MethodPost, "/gateways/gw1/revert", "gateway", "gw1", ActionRevert},
		{http.MethodPut, "/gateways/gw1/variables/API_URL", "gateway_variable", "API_URL", ActionUpdate},
		{http.MethodPost, "/gateways/gw1/secrets", "gateway_secret", "", ActionCreate},
		{http.MethodPost, "/configuration-versions", "configuration_version", "", ActionCreate},
	} {
		s.Run(tc.method+" "+tc.path, func() {
			s.False(isExcluded(tc.path))
			route, id, ok := matchManagementRoute(tc.method, tc.path)

			s.Require().True(ok)
			s.Equal(tc.resource, route.resource)
			s.Equal(tc.id, id)
			s.Equal(tc.action, route.actionFor(tc.method, http.StatusOK))
		})
	}
}

func (s *RoutesTestSuite) TestRoutesOutsideTheManagementAPIsAreExcluded() {
	for _, path := range []string{
		"/oauth2/token", "/oauth2/dcr/register", "/oauth2/dcr/register/c1", "/ou/ou1/oauth2/token",
		"/flow/execute", "/.well-known/openid-configuration", "/auth/credentials/authenticate",
		"/register/passkey/start", "/access/evaluation", "/openid4vp/response", "/openid4vp/status/s1",
		"/openid4vci/credential", "/openid4vci/credential-offer/o1", "/openid4vci/nonce",
		"/design/resolve/flow", "/health/liveness", "/gate/signin", "/console/home", "/error/page", "/mcp",
		"/export", "/cimd/preview", "/users/me", "/users/me/update-credentials", "/scim/v2/Me",
		"/scim/v2/Users/.search", "/scim/v2/Groups/.search",
	} {
		s.True(isExcluded(path), path)
	}
}

// An exclusion covers whole path segments, so a management family that shares its first letters is
// not swallowed by it.
func (s *RoutesTestSuite) TestAnExclusionDoesNotSwallowASimilarFamily() {
	for _, path := range []string{
		"/flows", "/gateways", "/openid4vci/credential-configurations", "/exports", "/users/meet",
		"/designs",
	} {
		s.False(isExcluded(path), path)
	}
}

func (s *RoutesTestSuite) TestARouteOutsideTheTableIsNotMatched() {
	for _, tc := range []struct{ method, path string }{
		{http.MethodPost, "/widgets"},
		{http.MethodPost, "/users/u1/unknown"},
		{http.MethodPost, "/users/"},
		{http.MethodPut, "/variables"},
		{http.MethodPut, "/gateways/gw1/unknown"},
	} {
		_, _, ok := matchManagementRoute(tc.method, tc.path)
		s.False(ok, tc.method+" "+tc.path)
	}
}

// A 201 is a create whatever the method, and a route with its own action keeps it.
func (s *RoutesTestSuite) TestTheActionOfAMatchedRoute() {
	variable, _, ok := matchManagementRoute(http.MethodPut, "/variables/API_URL")
	s.Require().True(ok)
	s.Equal(ActionCreate, variable.actionFor(http.MethodPut, http.StatusCreated))
	s.Equal(ActionUpdate, variable.actionFor(http.MethodPut, http.StatusOK))
	s.Equal(ActionDelete, variable.actionFor(http.MethodDelete, http.StatusNoContent))

	restore, _, ok := matchManagementRoute(http.MethodPost, "/flows/f1/restore")
	s.Require().True(ok)
	s.Equal(ActionRestore, restore.actionFor(http.MethodPost, http.StatusCreated))
}

// Only the import routes are recorded beside the service events of a call.
func (s *RoutesTestSuite) TestOnlyTheImportRoutesAreRecordedBesideServiceEvents() {
	var recorded []string
	for _, route := range managementRoutes {
		if route.alwaysRecorded {
			recorded = append(recorded, route.path)
		}
	}
	s.Equal([]string{"/import", "/import/delete"}, recorded)
}
