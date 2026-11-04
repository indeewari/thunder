// Copyright 2026 The ThunderID Authors
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"context"
	"errors"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/suite"

	"github.com/thunder-id/thunderid/internal/system/constants"
	"github.com/thunder-id/thunderid/internal/system/log"
	"github.com/thunder-id/thunderid/internal/system/log/rollingfile"
	"github.com/thunder-id/thunderid/tests/mocks/eventbusmock"
)

const (
	logFileName       = "audit.log"
	suppressedWarning = "Refused calls exceed the audit rate limit"
)

type RejectionTestSuite struct {
	suite.Suite
}

func TestRejectionTestSuite(t *testing.T) {
	suite.Run(t, new(RejectionTestSuite))
}

func (s *RejectionTestSuite) TestACallWithoutCredentialsIsDeniedForAnAnonymousActor() {
	bus, events := newAuditBus(s.T())
	handler := newServingChain(s.T(), bus, testMux("POST /variables"))

	response := serve(handler, newRequest(http.MethodPost, "/variables", "", ""))

	s.Equal(http.StatusUnauthorized, response.Code)
	evt := awaitEvent(s.T(), events)
	s.Equal("variable.create", evt.env.Name, "a refused attempt keeps the name of the route")
	s.Equal(response.Header().Get(constants.CorrelationIDHeaderName), evt.env.TraceID)
	s.Equal(Actor{Type: ActorTypeAnonymous}, evt.payload.Actor())
	s.Equal(Ref{Type: "variable"}, evt.payload.Target())
	s.Equal(ActionCreate, evt.payload.Action())
	s.Equal(OutcomeDenied("unauthorized"), evt.payload.Outcome())
	s.Equal(Client{Address: testClientIP, UserAgent: testUserAgent}, evt.payload.Client())
}

func (s *RejectionTestSuite) TestARefusedTokenIsDeniedForAnAnonymousActor() {
	bus, events := newAuditBus(s.T())
	handler := newServingChain(s.T(), bus, testMux("DELETE /users/{id}"))
	r := newRequest(http.MethodDelete, "/users/u1", "not-a-token", "")

	s.Equal(http.StatusUnauthorized, serve(handler, r).Code)

	evt := awaitEvent(s.T(), events)
	s.Equal(Actor{Type: ActorTypeAnonymous}, evt.payload.Actor())
	s.Equal(Ref{Type: "user"}, evt.payload.Target(), "a refused request records no caller-chosen ID")
	s.Equal(ActionDelete, evt.payload.Action())
}

func (s *RejectionTestSuite) TestACallWithoutPermissionIsDeniedForTheVerifiedSubject() {
	bus, events := newAuditBus(s.T())
	handler := newServingChain(s.T(), bus, testMux("POST /users"))
	token := accessToken(s.T(), map[string]interface{}{"sub": testUserID, "scope": "openid"})

	s.Equal(http.StatusForbidden, serve(handler, newRequest(http.MethodPost, "/users", token, "")).Code)

	evt := awaitEvent(s.T(), events)
	s.Equal("user.create", evt.env.Name)
	s.Equal(Actor{Type: ActorTypeUser, ID: testUserID}, evt.payload.Actor())
	s.Equal(Ref{Type: "user"}, evt.payload.Target())
	s.Equal(OutcomeDenied("forbidden"), evt.payload.Outcome())
}

func (s *RejectionTestSuite) TestARefusedCallOutsideTheTableHasTheNeutralTarget() {
	bus, events := newAuditBus(s.T())
	handler := newServingChain(s.T(), bus, testMux("POST /widgets"))

	serve(handler, newRequest(http.MethodPost, "/widgets", "", ""))

	evt := awaitEvent(s.T(), events)
	s.Equal(EventManagementRequest, evt.env.Name)
	s.Equal(Ref{Type: unmappedTargetType}, evt.payload.Target())
	s.Equal(OutcomeDenied("unauthorized"), evt.payload.Outcome())
}

// A refused read is not audited, so unauthenticated browser requests do not flood the stream.
func (s *RejectionTestSuite) TestARefusedReadIsNotAudited() {
	bus, events := newAuditBus(s.T())
	handler := newServingChain(s.T(), bus, testMux("GET /users", "HEAD /favicon.ico", "POST "+barrierPath))

	s.Equal(http.StatusUnauthorized, serve(handler, newRequest(http.MethodGet, "/users", "", "")).Code)
	s.Equal(http.StatusUnauthorized, serve(handler, newRequest(http.MethodHead, "/favicon.ico", "", "")).Code)

	s.Equal(http.StatusOK, serve(handler, newRequest(http.MethodPost, barrierPath,
		accessToken(s.T(), map[string]interface{}{"sub": testUserID}), "")).Code)
	evt := awaitEvent(s.T(), events)
	s.Equal(EventManagementRequest, evt.env.Name)
	s.Equal(OutcomeSucceeded, evt.payload.Outcome(), "a refused read published an event")
}

func (s *RejectionTestSuite) TestAFailingBusLeavesTheRefusalAlone() {
	healthy, _ := newAuditBus(s.T())
	failing := eventbusmock.NewEventBusInterfaceMock(s.T())
	failing.EXPECT().Publish(mock.Anything, mock.Anything).Return(errors.New("bus is shut down")).Once()
	request := func() *http.Request { return newRequest(http.MethodPost, "/variables", "", "") }

	expected := serve(newServingChain(s.T(), healthy, testMux("POST /variables")), request())
	actual := serve(newServingChain(s.T(), failing, testMux("POST /variables")), request())

	s.Equal(expected.Code, actual.Code)
	s.Equal(expected.Header().Get("WWW-Authenticate"), actual.Header().Get("WWW-Authenticate"))
	s.Equal(expected.Body.String(), actual.Body.String())
}

func (s *RejectionTestSuite) TestANilBusIsRefused() {
	hook, err := RejectionHook(nil)

	s.ErrorIs(err, errNilBus)
	s.Nil(hook)
}

// fakeClock is a clock a test moves by hand.
type fakeClock struct {
	now time.Time
}

func (c *fakeClock) read() time.Time { return c.now }

// newLimitedRecorder returns a rejection recorder on a bus mock that accepts expected publishes, with
// a clock the test moves.
func (s *RejectionTestSuite) newLimitedRecorder(expected int) (*rejectionRecorder, *fakeClock) {
	bus := eventbusmock.NewEventBusInterfaceMock(s.T())
	if expected > 0 {
		bus.EXPECT().Publish(mock.Anything, mock.Anything).Return(nil).Times(expected)
	}
	clock := &fakeClock{now: time.Date(2026, 11, 5, 9, 0, 0, 0, time.UTC)}
	return newRejectionRecorder(bus, clock.read), clock
}

// refuse reports n refused calls to the recorder.
func refuse(recorder *rejectionRecorder, n int) {
	for range n {
		recorder.record(context.Background(), httptest.NewRequest(http.MethodPost, "/users", nil),
			http.StatusUnauthorized)
	}
}

// captureLog sends the process logger to a file until the test ends and returns a reader for it.
func (s *RejectionTestSuite) captureLog() func() string {
	dir := s.T().TempDir()
	s.Require().NoError(log.GetLogger().Configure(log.OutputOptions{
		FileEnabled: true,
		File:        rollingfile.Config{Path: filepath.Join(dir, logFileName)},
	}))
	s.T().Cleanup(func() {
		s.NoError(log.GetLogger().Configure(log.OutputOptions{ConsoleEnabled: true}))
	})
	return func() string {
		content, err := fs.ReadFile(os.DirFS(dir), logFileName)
		if os.IsNotExist(err) {
			return ""
		}
		s.Require().NoError(err)
		return string(content)
	}
}

func (s *RejectionTestSuite) TestRefusalsWithinTheBurstAreAllPublished() {
	recorder, _ := s.newLimitedRecorder(refusedEventsBurst)

	refuse(recorder, refusedEventsBurst)

	s.Zero(recorder.suppressed.Load())
}

func (s *RejectionTestSuite) TestRefusalsBeyondTheBurstAreSuppressedAndCounted() {
	recorder, _ := s.newLimitedRecorder(refusedEventsBurst)

	refuse(recorder, refusedEventsBurst+50)

	s.Equal(uint64(50), recorder.suppressed.Load())
}

func (s *RejectionTestSuite) TestTheLimitRefillsOverTime() {
	recorder, clock := s.newLimitedRecorder(refusedEventsBurst + refusedEventsPerSecond)
	refuse(recorder, refusedEventsBurst)

	clock.now = clock.now.Add(time.Second)
	refuse(recorder, refusedEventsPerSecond+1)

	s.Equal(uint64(1), recorder.suppressed.Load())
}

// A sustained flood is admitted at the steady rate, and a long pause does not admit more than a burst.
func (s *RejectionTestSuite) TestTheLimitNeverExceedsTheBurst() {
	recorder, clock := s.newLimitedRecorder(refusedEventsBurst)

	clock.now = clock.now.Add(time.Hour)
	refuse(recorder, refusedEventsBurst+1)

	s.Equal(uint64(1), recorder.suppressed.Load())
}

func (s *RejectionTestSuite) TestTheSuppressedWarningIsRateLimited() {
	read := s.captureLog()
	recorder, clock := s.newLimitedRecorder(refusedEventsBurst)
	refuse(recorder, refusedEventsBurst+10)
	s.Equal(1, strings.Count(read(), suppressedWarning), "the first suppression warns")

	clock.now = clock.now.Add(suppressedWarningInterval - time.Second)
	for range 10 {
		recorder.noteSuppressed(context.Background())
	}
	s.Equal(1, strings.Count(read(), suppressedWarning), "one warning within the interval")

	clock.now = clock.now.Add(time.Second)
	recorder.noteSuppressed(context.Background())
	logged := read()
	s.Equal(2, strings.Count(logged, suppressedWarning), "a second warning once the interval passed")
	s.Contains(logged, "suppressed=21")
	s.Equal(uint64(21), recorder.suppressed.Load())
}
