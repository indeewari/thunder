// Copyright 2026 The ThunderID Authors
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/suite"

	"github.com/thunder-id/thunderid/internal/system/eventbus"
)

type CatalogTestSuite struct {
	suite.Suite
}

func TestCatalogTestSuite(t *testing.T) {
	suite.Run(t, new(CatalogTestSuite))
}

func (s *CatalogTestSuite) TestEveryAuditedEventRequiresTheAuditPayload() {
	catalog := Catalog()

	s.Equal([]eventbus.Category{CategoryAudit}, catalog[EventManagementRequest])
	for name, categories := range catalog {
		s.Contains(categories, CategoryAudit, name)
	}
}

func (s *CatalogTestSuite) TestTheCatalogIsACopy() {
	Catalog()[EventManagementRequest][0] = "changed"
	delete(Catalog(), EventManagementRequest)

	s.Equal([]eventbus.Category{CategoryAudit}, Catalog()[EventManagementRequest])
}

// The user events a service publishes are the names the route table derives for the user routes, so a
// service event and the wrapper's fallback for the same call never differ.
func (s *CatalogTestSuite) TestTheUserEventsAreTheNamesTheRouteTableDerives() {
	for _, tc := range []struct {
		name, method, path string
	}{
		{EventUserCreate, http.MethodPost, "/users"},
		{EventUserUpdate, http.MethodPut, "/users/u1"},
		{EventUserDelete, http.MethodDelete, "/users/u1"},
	} {
		route, _, ok := matchManagementRoute(tc.method, tc.path)
		s.Require().True(ok, tc.path)
		s.Equal(TargetTypeUser, route.resource)
		s.Equal(tc.name, route.eventName(route.actionFor(tc.method, http.StatusOK)))
		s.Contains(Catalog(), tc.name)
	}
}
