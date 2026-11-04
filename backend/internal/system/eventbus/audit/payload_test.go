// Copyright 2026 The ThunderID Authors
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"context"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/stretchr/testify/suite"

	"github.com/thunder-id/thunderid/internal/system/eventbus"
)

var testTarget = Ref{Type: "variables", ID: "API_URL"}

type PayloadTestSuite struct {
	suite.Suite
}

func TestPayloadTestSuite(t *testing.T) {
	suite.Run(t, new(PayloadTestSuite))
}

func (s *PayloadTestSuite) TestAnUnauthenticatedContextIsAnonymous() {
	payload := NewPayload(context.Background(), testTarget, ActionUpdate, OutcomeSucceeded)

	s.Equal(Actor{Type: ActorTypeAnonymous}, payload.Actor())
	s.Equal(Ref{}, payload.OnBehalfOf())
}

func (s *PayloadTestSuite) TestTheManagementAPIKeyIsTheSystemActor() {
	ctx := securedContext(s.T(), "", testAPIKey)

	payload := NewPayload(ctx, testTarget, ActionUpdate, OutcomeSucceeded)

	s.Equal(Actor{Type: ActorTypeSystem, ID: "management-api-key"}, payload.Actor())
}

func (s *PayloadTestSuite) TestTheActorComesFromTheVerifiedToken() {
	cases := []struct {
		name       string
		claims     map[string]interface{}
		actor      Actor
		onBehalfOf Ref
	}{
		{
			name:   "a user token carries no sub_type",
			claims: map[string]interface{}{"sub": testUserID},
			actor:  Actor{Type: ActorTypeUser, ID: testUserID},
		},
		{
			name:   "a client credentials token of an application",
			claims: map[string]interface{}{"sub": testAppID, "sub_type": "application"},
			actor:  Actor{Type: ActorTypeApplication, ID: testAppID},
		},
		{
			name:   "a client credentials token of an agent",
			claims: map[string]interface{}{"sub": testAgentID, "sub_type": "agent"},
			actor:  Actor{Type: ActorTypeAgent, ID: testAgentID},
		},
		{
			name:   "an unknown sub_type is not trusted",
			claims: map[string]interface{}{"sub": testUserID, "sub_type": "system"},
			actor:  Actor{Type: ActorTypeUser, ID: testUserID},
		},
		{
			name: "an act claim makes the actor an agent acting for the subject",
			claims: map[string]interface{}{
				"sub": testUserID,
				"act": map[string]interface{}{"sub": testAgentID},
			},
			actor:      Actor{Type: ActorTypeAgent, ID: testAgentID},
			onBehalfOf: Ref{Type: string(ActorTypeUser), ID: testUserID},
		},
		{
			name:   "a token whose sub is the key's subject is not the key",
			claims: map[string]interface{}{"sub": "management-api-key"},
			actor:  Actor{Type: ActorTypeUser, ID: "management-api-key"},
		},
	}
	for _, tc := range cases {
		s.Run(tc.name, func() {
			ctx := securedContext(s.T(), accessToken(s.T(), tc.claims), "")

			payload := NewPayload(ctx, testTarget, ActionUpdate, OutcomeSucceeded)

			s.Equal(tc.actor, payload.Actor())
			s.Equal(tc.onBehalfOf, payload.OnBehalfOf())
		})
	}
}

func (s *PayloadTestSuite) TestValidate() {
	cases := []struct {
		name    string
		payload Payload
		err     error
	}{
		{"a succeeded outcome needs no reason", NewPayload(context.Background(), testTarget, ActionCreate,
			OutcomeSucceeded), nil},
		{"a denied outcome with a reason", NewPayload(context.Background(), testTarget, ActionCreate,
			OutcomeDenied("http_403")), nil},
		{"a failed outcome with a reason", NewPayload(context.Background(), testTarget, ActionCreate,
			OutcomeFailed("http_500")), nil},
		{"a denied outcome without a reason", NewPayload(context.Background(), testTarget, ActionCreate,
			OutcomeDenied("")), errMissingReason},
		{"a failed outcome without a reason", NewPayload(context.Background(), testTarget, ActionCreate,
			OutcomeFailed("")), errMissingReason},
		{"a free text reason", NewPayload(context.Background(), testTarget, ActionCreate,
			OutcomeFailed("Password was wrong for alice")), errInvalidReason},
		{"an unknown result", NewPayload(context.Background(), testTarget, ActionCreate,
			Outcome{Result: "maybe"}), errUnknownResult},
		{"a target without a type", NewPayload(context.Background(), Ref{ID: "API_URL"}, ActionCreate,
			OutcomeSucceeded), errMissingTarget},
		{"an empty action", NewPayload(context.Background(), testTarget, "", OutcomeSucceeded),
			errMissingAction},
	}
	for _, tc := range cases {
		s.Run(tc.name, func() {
			s.ErrorIs(tc.payload.Validate(), tc.err)
		})
	}
}

// The bus calls Validate, so a payload that breaks the outcome rule is refused at Publish.
func (s *PayloadTestSuite) TestPublishRefusesADeniedOutcomeWithoutAReason() {
	bus, _ := newAuditBus(s.T())
	ctx := context.Background()

	err := bus.Publish(ctx, eventbus.NewEvent(ctx, EventManagementRequest).
		With(NewPayload(ctx, testTarget, ActionDelete, OutcomeDenied(""))))

	s.ErrorIs(err, errMissingReason)
}

// A target ID is cut to its first 128 characters, and a multi-byte character is never split.
func (s *PayloadTestSuite) TestEveryIDIsCutTo128Characters() {
	long := strings.Repeat("ü", maxIDLength+20)
	exact := strings.Repeat("a", maxIDLength)
	ctx := securedContext(s.T(), accessToken(s.T(), map[string]interface{}{"sub": long}), "")

	payload := NewPayload(ctx, Ref{Type: "variable", ID: long}, ActionUpdate, OutcomeSucceeded).
		WithSubject(Ref{Type: "user", ID: long}).
		WithOnBehalfOf(Ref{Type: "user", ID: long})

	ids := []string{payload.Target().ID, payload.Subject().ID, payload.OnBehalfOf().ID, payload.Actor().ID}
	for _, id := range ids {
		s.True(utf8.ValidString(id))
		s.Equal(strings.Repeat("ü", maxIDLength), id)
	}
	s.Equal(exact, NewPayload(ctx, Ref{Type: "variable", ID: exact}, ActionUpdate, OutcomeSucceeded).Target().ID)
}

func (s *PayloadTestSuite) TestBuildersReturnIndependentCopies() {
	details := map[string]string{"grant_type": "client_credentials"}
	base := NewPayload(context.Background(), testTarget, ActionCreate, OutcomeSucceeded)

	built := base.WithSubject(Ref{Type: "user", ID: testUserID}).
		WithOnBehalfOf(Ref{Type: "user", ID: testUserID}).
		WithClient(Client{Address: testClientIP, UserAgent: testUserAgent}).
		WithDetails(details)
	details["grant_type"] = "changed"
	built.Details()["grant_type"] = "changed again"

	s.Equal(Ref{}, base.Subject(), "the receiver is unchanged")
	s.Equal(Ref{Type: "user", ID: testUserID}, built.Subject())
	s.Equal(Ref{Type: "user", ID: testUserID}, built.OnBehalfOf())
	s.Equal(Client{Address: testClientIP, UserAgent: testUserAgent}, built.Client())
	s.Equal(map[string]string{"grant_type": "client_credentials"}, built.Details())
	s.Equal(testTarget, built.Target())
	s.Equal(ActionCreate, built.Action())
	s.Equal(OutcomeSucceeded, built.Outcome())
	s.Equal(CategoryAudit, built.Category())
}
