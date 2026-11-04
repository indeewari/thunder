// Copyright 2026 The ThunderID Authors
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"context"
	"testing"

	"github.com/stretchr/testify/suite"

	"github.com/thunder-id/thunderid/internal/system/eventbus"
)

type SinkTestSuite struct {
	suite.Suite
}

func TestSinkTestSuite(t *testing.T) {
	suite.Run(t, new(SinkTestSuite))
}

func (s *SinkTestSuite) TestANilSinkIsRefused() {
	bus, _ := newAuditBus(s.T())

	s.ErrorIs(Subscribe(bus, "nil-sink", nil), errNilSink)
}

// A sink receives only the detail keys the event's catalog entry allows, whatever the publisher set.
func (s *SinkTestSuite) TestASinkReceivesOnlyAllowlistedDetails() {
	bus, events := newAuditBus(s.T())
	ctx := context.Background()
	payload := NewPayload(ctx, testTarget, ActionUpdate, OutcomeSucceeded).
		WithDetails(map[string]string{"value": "a variable value", "client_secret": "s3cr3t"})

	s.Require().NoError(bus.Publish(ctx, eventbus.NewEvent(ctx, EventManagementRequest).With(payload)))

	s.Empty(awaitEvent(s.T(), events).payload.Details())
}

func (s *SinkTestSuite) TestWithAllowedDetailsKeepsOnlyTheListedKeys() {
	payload := NewPayload(context.Background(), testTarget, ActionUpdate, OutcomeSucceeded).
		WithDetails(map[string]string{"grant_type": "client_credentials", "client_secret": "s3cr3t"})

	s.Equal(map[string]string{"grant_type": "client_credentials"},
		payload.withAllowedDetails([]string{"grant_type", "scope"}).Details())
	s.Len(payload.Details(), 2, "the receiver is unchanged")
}
