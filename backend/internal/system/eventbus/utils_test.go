// Copyright 2026 The ThunderID Authors
// SPDX-License-Identifier: Apache-2.0

package eventbus

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/suite"
)

const publishFailure = "Failed to publish an event"

type UtilsTestSuite struct {
	busSuite
}

func TestUtilsTestSuite(t *testing.T) {
	suite.Run(t, new(UtilsTestSuite))
}

func (s *UtilsTestSuite) TestTryPublishDeliversTheEvent() {
	readLog := s.captureLog()
	bus := s.newBus(8, time.Second)
	defer s.shutdown(bus)
	rec := subscribe[payloadOne](&s.busSuite, bus, "one", nil)

	TryPublish(context.Background(), bus, NewEvent(context.Background(), testEventName).With(payloadOne{value: "a"}))

	s.eventually(func() bool { return rec.count() == 1 })
	s.NotContains(readLog(), publishFailure)
}

func (s *UtilsTestSuite) TestTryPublishLogsAndReturnsWhenPublishFails() {
	readLog := s.captureLog()
	bus := s.newBus(8, time.Second)
	rec := subscribe[payloadOne](&s.busSuite, bus, "one", nil)

	TryPublish(context.Background(), bus, NewEvent(context.Background(), testEventName))
	s.NotPanics(func() { TryPublish(context.Background(), bus, nil) })
	s.shutdown(bus)

	s.Zero(rec.count())
	output := readLog()
	s.Contains(output, publishFailure)
	s.Contains(output, testEventName)
	s.Contains(output, errNoPayload.Error())
	s.Contains(output, errNilEvent.Error())
	s.Contains(output, "EventBus")
}

func (s *UtilsTestSuite) TestTryPublishNeverLogsAnInvalidName() {
	readLog := s.captureLog()
	bus := s.newBus(8, time.Second)

	TryPublish(context.Background(), bus, NewEvent(context.Background(), "user.created\r\nforged=1").With(payloadOne{}))

	output := readLog()
	s.Contains(output, publishFailure)
	s.Contains(output, "event="+invalidEventName)
	s.NotContains(output, "forged")
}

func (s *UtilsTestSuite) TestSubscriberIsRegisteredForTheCategoryOfItsPayload() {
	bus := s.newBus(8, time.Second)
	defer s.shutdown(bus)

	subscribe[payloadTwo](&s.busSuite, bus, "two", nil)

	s.Equal(categoryTwo, s.stats(bus)[0].Category)
}

func (s *UtilsTestSuite) TestNilSubscriberAndInvalidIDsAreRejected() {
	bus := s.newBus(8, time.Second)
	defer s.shutdown(bus)
	subscribe[payloadOne](&s.busSuite, bus, "same", nil)

	s.ErrorIs(Subscribe[payloadOne](bus, "nil", nil), errNilHandler)
	s.ErrorIs(Subscribe[payloadOne](bus, "same", NewSubscriberMock[payloadOne](s.T())), errDuplicateSubscriberID)
	s.ErrorIs(Subscribe[payloadOne](bus, "", NewSubscriberMock[payloadOne](s.T())), errEmptySubscriberID)
}

func (s *UtilsTestSuite) TestPayloadTypeThatCannotReportItsCategoryIsRejected() {
	bus := s.newBus(8, time.Second)
	defer s.shutdown(bus)

	s.ErrorIs(Subscribe[Payload](bus, "interface", NewSubscriberMock[Payload](s.T())), errUnsupportedPayloadType)
	s.ErrorIs(Subscribe[*pointerPayload](bus, "pointer", NewSubscriberMock[*pointerPayload](s.T())),
		errUnsupportedPayloadType)
	s.ErrorIs(Subscribe[panickingPayload](bus, "panicking", NewSubscriberMock[panickingPayload](s.T())),
		errUnsupportedPayloadType)
	s.Empty(s.stats(bus))
}

func (s *UtilsTestSuite) TestPayloadOfAnotherTypeInTheSameCategoryIsAFailedDelivery() {
	bus := s.newBus(8, time.Second)
	defer s.shutdown(bus)
	rec := subscribe[payloadOne](&s.busSuite, bus, "one", nil)

	s.Require().NoError(s.publish(bus, testEventName, checkedPayload{value: "v"}))
	s.Require().NoError(s.publish(bus, testEventName, payloadOne{value: "a"}))

	s.eventually(func() bool {
		stats := s.stats(bus)[0]
		return stats.Failed == 1 && stats.Delivered == 1
	})
	_, payloads := rec.received()
	s.Equal([]payloadOne{{value: "a"}}, payloads)
}
