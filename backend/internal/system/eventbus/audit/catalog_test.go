// Copyright 2026 The ThunderID Authors
// SPDX-License-Identifier: Apache-2.0

package audit

import (
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
