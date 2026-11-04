// Copyright 2026 The ThunderID Authors
// SPDX-License-Identifier: Apache-2.0

package eventbus

import (
	"context"
	"strings"
	"testing"

	"github.com/stretchr/testify/suite"

	sysContext "github.com/thunder-id/thunderid/internal/system/context"
	"github.com/thunder-id/thunderid/internal/system/deployment"
)

// validTraceParent is a W3C version 00 traceparent.
const validTraceParent = "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01"

type EventTestSuite struct {
	suite.Suite
}

func TestEventTestSuite(t *testing.T) {
	suite.Run(t, new(EventTestSuite))
}

func (s *EventTestSuite) TestNameGrammar() {
	longest := strings.Repeat("a", 31) + "." + strings.Repeat("b", 32)
	valid := []string{"user.created", "token.issued", "user.credential.changed", "a.b.c.d", "x1.y_2", longest}
	invalid := []string{"", "USER_CREATED", "user", "User.created", "user..created", ".user.created",
		"user.created.", "1user.created", "a.b.c.d.e", "user.created now", "user-created.x", longest + "b",
		"user.created\n"}

	s.Len(longest, maxEventNameLength)
	for _, name := range valid {
		s.NoError(NewEvent(context.Background(), name).With(payloadOne{}).validate(), name)
	}
	for _, name := range invalid {
		s.ErrorIs(NewEvent(context.Background(), name).With(payloadOne{}).validate(), errInvalidEventName, name)
	}
}

func (s *EventTestSuite) TestEventWithoutPayloadIsRejected() {
	s.ErrorIs(NewEvent(context.Background(), testEventName).validate(), errNoPayload)
}

func (s *EventTestSuite) TestNilPayloadAndDuplicateCategoryAreRejected() {
	s.ErrorIs(NewEvent(context.Background(), testEventName).With(nil).validate(), errNilPayload)
	s.ErrorIs(NewEvent(context.Background(), testEventName).With(payloadOne{}).With(payloadOne{}).validate(),
		errDuplicateCategory)
	s.ErrorIs(NewEvent(context.Background(), testEventName).With(payloadOne{}).With(checkedPayload{value: "v"}).
		validate(), errDuplicateCategory)
}

func (s *EventTestSuite) TestFirstErrorIsKept() {
	evt := NewEvent(context.Background(), "BAD").With(nil).With(payloadOne{})

	s.ErrorIs(evt.validate(), errInvalidEventName)
}

func (s *EventTestSuite) TestPayloadsPutEventInTheirCategories() {
	evt := NewEvent(context.Background(), testEventName).With(payloadOne{value: "a"}).With(payloadTwo{value: "b"})

	s.Require().NoError(evt.validate())
	s.Len(evt.payloads, 2)
	s.Contains(evt.payloads, categoryOne)
	s.Contains(evt.payloads, categoryTwo)
}

func (s *EventTestSuite) TestPayloadThatFailsItsOwnValidationIsRejected() {
	err := NewEvent(context.Background(), testEventName).With(checkedPayload{}).validate()

	s.ErrorIs(err, errInvalidPayload)
	s.ErrorIs(err, errPayloadIncomplete)
	s.Contains(err.Error(), string(categoryOne))
	s.NoError(NewEvent(context.Background(), testEventName).With(checkedPayload{value: "v"}).validate())
}

func (s *EventTestSuite) TestRequestFieldsAreTakenFromContext() {
	ctx := sysContext.WithTraceID(context.Background(), "trace-1")
	ctx = deployment.WithID(ctx, "deployment-1")

	evt := NewEvent(ctx, testEventName).With(payloadOne{})

	s.Equal(testEventName, evt.envelope.Name)
	s.Equal("trace-1", evt.envelope.TraceID)
	s.Equal("deployment-1", evt.envelope.DeploymentID)
}

func (s *EventTestSuite) TestTraceIDIsEmptyWhenTheContextHasNone() {
	evt := NewEvent(context.Background(), testEventName).With(payloadOne{})

	s.Empty(evt.envelope.TraceID)
}

func (s *EventTestSuite) TestAValidTraceParentIsCarried() {
	evt := NewEvent(WithTraceParent(context.Background(), validTraceParent), testEventName).With(payloadOne{})

	s.Equal(validTraceParent, evt.envelope.TraceParent)
}

func (s *EventTestSuite) TestAnInvalidTraceParentIsIgnoredAndNoneIsGenerated() {
	for _, value := range []string{
		"",
		"garbage",
		"01-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01",
		"00-0AF7651916CD43DD8448EB211C80319C-b7ad6b7169203331-01",
		validTraceParent + " ",
		"00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331",
		"00-00000000000000000000000000000000-b7ad6b7169203331-01",
		"00-0af7651916cd43dd8448eb211c80319c-0000000000000000-01",
	} {
		evt := NewEvent(WithTraceParent(context.Background(), value), testEventName).With(payloadOne{})

		s.Empty(evt.envelope.TraceParent, value)
	}
	s.Empty(NewEvent(context.Background(), testEventName).envelope.TraceParent, "none is generated")
}

func (s *EventTestSuite) TestPointerPayloadIsRejected() {
	var typedNil *pointerPayload

	s.ErrorIs(NewEvent(context.Background(), testEventName).With(&pointerPayload{category: categoryOne}).validate(),
		errPointerPayload)
	s.ErrorIs(NewEvent(context.Background(), testEventName).With(typedNil).validate(), errPointerPayload)
}

func (s *EventTestSuite) TestPanickingPayloadIsRejectedWithoutPanicking() {
	s.NotPanics(func() {
		s.ErrorIs(NewEvent(context.Background(), testEventName).With(panickingPayload{}).validate(),
			errPayloadPanicked)
		s.ErrorIs(NewEvent(context.Background(), testEventName).With(panickingValidatorPayload{}).validate(),
			errPayloadPanicked)
	})
}

func (s *EventTestSuite) TestNameOfANilEventIsEmpty() {
	var evt *Event

	s.Empty(evt.Name())
	s.ErrorIs(evt.validate(), errNilEvent)
}
