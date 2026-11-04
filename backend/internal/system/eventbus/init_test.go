// Copyright 2026 The ThunderID Authors
// SPDX-License-Identifier: Apache-2.0

package eventbus

import (
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/suite"

	"github.com/thunder-id/thunderid/internal/system/utils"
)

type InitTestSuite struct {
	busSuite
}

func TestInitTestSuite(t *testing.T) {
	suite.Run(t, new(InitTestSuite))
}

func (s *InitTestSuite) TestUnsupportedDeliveryFailsStartup() {
	bus, stopper, err := Initialize(Config{Source: testSource,
		Delivery: map[Category]DeliveryMode{categoryOne: DeliveryBestEffort, categoryTwo: "at_least_once"}})

	s.Nil(bus)
	s.Nil(stopper)
	s.ErrorIs(err, errUnsupportedDelivery)
	s.Contains(err.Error(), `"at_least_once"`)
	s.Contains(err.Error(), string(categoryTwo))
}

func (s *InitTestSuite) TestBestEffortAndUnsetDeliveryAreAccepted() {
	for _, mode := range []DeliveryMode{"", DeliveryBestEffort} {
		bus := s.newBusWith(Config{Delivery: map[Category]DeliveryMode{categoryOne: mode}})
		rec := subscribe[payloadOne](&s.busSuite, bus, "one", nil)
		s.Require().NoError(s.publish(bus, testEventName, payloadOne{}))
		s.shutdown(bus)
		s.Equal(1, rec.count(), mode)
	}
}

func (s *InitTestSuite) TestEmptySourceFailsStartup() {
	bus, stopper, err := Initialize(Config{InstanceID: testInstanceID})

	s.Nil(bus)
	s.Nil(stopper)
	s.ErrorIs(err, errEmptySource)
}

func (s *InitTestSuite) TestNegativeSizesAndTimeoutsFailStartup() {
	cases := []struct {
		cfg Config
		err error
	}{
		{Config{Source: testSource, QueueSize: -1}, errInvalidQueueSize},
		{Config{Source: testSource, DeliveryTimeout: -time.Second}, errInvalidDeliveryTimeout},
		{Config{Source: testSource, ShutdownTimeout: -time.Second}, errInvalidShutdownTimeout},
	}
	for _, tc := range cases {
		bus, stopper, err := Initialize(tc.cfg)

		s.Nil(bus)
		s.Nil(stopper)
		s.ErrorIs(err, tc.err)
	}
}

func (s *InitTestSuite) TestDefaultsApplyAndInstanceIDFallsBackToHostName() {
	bus, stopper, err := Initialize(Config{Source: testSource})
	s.Require().NoError(err)
	defer stopper.Stop()
	hostName, err := os.Hostname()
	s.Require().NoError(err)

	service := bus.(*eventBusService)
	s.Equal(defaultQueueSize, service.queueSize)
	s.Equal(defaultDeliveryTimeout, service.timeout)
	s.Equal(defaultShutdownTimeout, service.shutdownTimeout)
	s.Equal(hostName, service.instanceID)
	s.Equal(testSource, service.source)
	s.True(utils.IsValidUUID(service.bootID))
}

func (s *InitTestSuite) TestBootIDDiffersPerInitialization() {
	first := s.newBusWith(Config{})
	defer s.shutdown(first)
	second := s.newBusWith(Config{})
	defer s.shutdown(second)

	s.NotEqual(first.(*eventBusService).bootID, second.(*eventBusService).bootID)
}

func (s *InitTestSuite) TestBusCannotBeAssertedToTheStopper() {
	bus := s.newBusWith(Config{})

	_, ok := bus.(StopperInterface)

	s.False(ok)
}
