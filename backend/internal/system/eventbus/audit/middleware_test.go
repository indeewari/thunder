// Copyright 2026 The ThunderID Authors
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/suite"

	"github.com/thunder-id/thunderid/internal/system/constants"
	"github.com/thunder-id/thunderid/internal/system/eventbus"
	"github.com/thunder-id/thunderid/tests/mocks/eventbusmock"
)

const (
	validTraceParent = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"
	// barrierPath is a mutating management route a test calls last, so the next event it receives
	// proves that nothing was published for the calls before it.
	barrierPath = "/barriers"
)

type MiddlewareTestSuite struct {
	suite.Suite
}

func TestMiddlewareTestSuite(t *testing.T) {
	suite.Run(t, new(MiddlewareTestSuite))
}

// serve sends r through handler and returns the response.
func serve(handler http.Handler, r *http.Request) *httptest.ResponseRecorder {
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, r)
	return recorder
}

// expectOnlyTheBarrier calls the barrier route and asserts it produced the next event, so the calls
// made before it produced none.
func (s *MiddlewareTestSuite) expectOnlyTheBarrier(handler http.Handler, events <-chan received, token string) {
	s.Equal(http.StatusOK, serve(handler, newRequest(http.MethodPost, barrierPath, token, "")).Code)
	evt := awaitEvent(s.T(), events)
	s.Equal(Ref{Type: "barriers"}, evt.payload.Target(), "an earlier call published an event")
}

func (s *MiddlewareTestSuite) TestAManagementCallPublishesOneEventFromTheRequest() {
	bus, events := newAuditBus(s.T())
	handler := newServingChain(s.T(), bus, testMux("POST /users"))
	token := accessToken(s.T(), map[string]interface{}{"sub": testUserID})
	r := newRequest(http.MethodPost, "/users?status=201", token, "")
	r.Header.Set(constants.TraceParentHeaderName, validTraceParent)

	response := serve(handler, r)

	s.Equal(http.StatusCreated, response.Code)
	evt := awaitEvent(s.T(), events)
	s.Equal("user.create", evt.env.Name)
	s.Equal(response.Header().Get(constants.CorrelationIDHeaderName), evt.env.TraceID,
		"the event and the access log share the trace id")
	s.Equal(validTraceParent, evt.env.TraceParent)
	s.Equal(testDeploymentID, evt.env.DeploymentID)
	s.Equal(testSource, evt.env.Source)
	s.Equal(Actor{Type: ActorTypeUser, ID: testUserID}, evt.payload.Actor())
	s.Equal(Ref{Type: "user"}, evt.payload.Target(), "a create has no ID yet")
	s.Equal(ActionCreate, evt.payload.Action())
	s.Equal(OutcomeSucceeded, evt.payload.Outcome())
	s.Equal(Client{Address: testClientIP, UserAgent: testUserAgent}, evt.payload.Client())
	s.Empty(evt.payload.Details())
}

func (s *MiddlewareTestSuite) TestTheTargetIDComesFromTheRouteWildcard() {
	bus, events := newAuditBus(s.T())
	handler := newServingChain(s.T(), bus, testMux("PUT /variables/{name}", "DELETE /variables/{name}"))

	s.Equal(http.StatusNoContent,
		serve(handler, newRequest(http.MethodPut, "/variables/API_URL?status=204", "", testAPIKey)).Code)
	s.Equal(http.StatusNoContent,
		serve(handler, newRequest(http.MethodDelete, "/variables/API_URL?status=204", "", testAPIKey)).Code)

	updated := awaitEvent(s.T(), events)
	s.Equal("variable.update", updated.env.Name)
	s.Equal(Actor{Type: ActorTypeSystem, ID: "management-api-key"}, updated.payload.Actor())
	s.Equal(Ref{Type: "variable", ID: "API_URL"}, updated.payload.Target())
	s.Equal(ActionUpdate, updated.payload.Action())
	deleted := awaitEvent(s.T(), events)
	s.Equal("variable.delete", deleted.env.Name)
	s.Equal(ActionDelete, deleted.payload.Action())
	s.Equal(updated.env.Seq+1, deleted.env.Seq)
}

func (s *MiddlewareTestSuite) TestAPutThatCreatesIsACreate() {
	bus, events := newAuditBus(s.T())
	handler := newServingChain(s.T(), bus, testMux("PUT /variables/{name}"))

	serve(handler, newRequest(http.MethodPut, "/variables/API_URL?status=201", "", testAPIKey))

	evt := awaitEvent(s.T(), events)
	s.Equal("variable.create", evt.env.Name)
	s.Equal(ActionCreate, evt.payload.Action())
	s.Equal(Ref{Type: "variable", ID: "API_URL"}, evt.payload.Target())
}

// A route with an action of its own keeps it, even when it answers 201.
func (s *MiddlewareTestSuite) TestAnActionRouteKeepsItsAction() {
	bus, events := newAuditBus(s.T())
	handler := newServingChain(s.T(), bus, testMux("POST /roles/{id}/assignments/add", "POST /flows/{flowId}/restore"))
	token := accessToken(s.T(), map[string]interface{}{"sub": testUserID})

	serve(handler, newRequest(http.MethodPost, "/roles/r1/assignments/add?status=201", token, ""))
	serve(handler, newRequest(http.MethodPost, "/flows/f1/restore?status=201", token, ""))

	added := awaitEvent(s.T(), events)
	s.Equal("role_assignment.add", added.env.Name)
	s.Equal(ActionAdd, added.payload.Action())
	s.Equal(Ref{Type: "role_assignment", ID: "r1"}, added.payload.Target())
	restored := awaitEvent(s.T(), events)
	s.Equal("flow.restore", restored.env.Name)
	s.Equal(Ref{Type: "flow", ID: "f1"}, restored.payload.Target())
}

// A family served by one catch-all route still names the resource it changed.
func (s *MiddlewareTestSuite) TestACatchAllRouteNamesTheResourceFromThePath() {
	bus, events := newAuditBus(s.T())
	handler := newServingChain(s.T(), bus, testMux("PUT /users/", "POST /groups/"))
	token := accessToken(s.T(), map[string]interface{}{"sub": testUserID})

	serve(handler, newRequest(http.MethodPut, "/users/u1", token, ""))
	serve(handler, newRequest(http.MethodPost, "/groups/g1/members/remove", token, ""))

	updated := awaitEvent(s.T(), events)
	s.Equal("user.update", updated.env.Name)
	s.Equal(Ref{Type: "user", ID: "u1"}, updated.payload.Target())
	removed := awaitEvent(s.T(), events)
	s.Equal("group_membership.remove", removed.env.Name)
	s.Equal(Ref{Type: "group_membership", ID: "g1"}, removed.payload.Target())
}

// A mutating route the table does not name is still recorded, under the generic name.
func (s *MiddlewareTestSuite) TestAnUnmappedManagementRouteIsRecordedUnderTheGenericName() {
	bus, events := newAuditBus(s.T())
	handler := newServingChain(s.T(), bus, testMux("PUT /widgets/{id}"))

	serve(handler, newRequest(http.MethodPut, "/widgets/w1?status=201",
		accessToken(s.T(), map[string]interface{}{"sub": testUserID}), ""))

	evt := awaitEvent(s.T(), events)
	s.Equal(EventManagementRequest, evt.env.Name)
	s.Equal(Ref{Type: "widgets", ID: "w1"}, evt.payload.Target())
	s.Equal(ActionCreate, evt.payload.Action())
}

func (s *MiddlewareTestSuite) TestTheOutcomeComesFromTheStatus() {
	bus, events := newAuditBus(s.T())
	handler := newServingChain(s.T(), bus, testMux("PATCH /users/{id}"))
	token := accessToken(s.T(), map[string]interface{}{"sub": testUserID})

	for _, tc := range []struct {
		status  int
		outcome Outcome
	}{
		{http.StatusOK, OutcomeSucceeded},
		{http.StatusNoContent, OutcomeSucceeded},
		{http.StatusFound, OutcomeSucceeded},
		{http.StatusBadRequest, OutcomeFailed("invalid_request")},
		{http.StatusUnauthorized, OutcomeDenied("unauthorized")},
		{http.StatusForbidden, OutcomeDenied("forbidden")},
		{http.StatusNotFound, OutcomeFailed("not_found")},
		{http.StatusConflict, OutcomeFailed("conflict")},
		{http.StatusUnprocessableEntity, OutcomeFailed("http_422")},
		{http.StatusTooManyRequests, OutcomeFailed("http_429")},
		{http.StatusInternalServerError, OutcomeFailed("server_error")},
		{http.StatusBadGateway, OutcomeFailed("server_error")},
	} {
		s.Run(strconv.Itoa(tc.status), func() {
			target := "/users/" + testUserID + "?status=" + strconv.Itoa(tc.status)
			s.Equal(tc.status, serve(handler, newRequest(http.MethodPatch, target, token, "")).Code)

			evt := awaitEvent(s.T(), events)
			s.Equal(tc.outcome, evt.payload.Outcome())
			s.Equal(Ref{Type: "user", ID: testUserID}, evt.payload.Target())
		})
	}
}

func (s *MiddlewareTestSuite) TestReadsAndPreflightsPublishNothing() {
	bus, events := newAuditBus(s.T())
	handler := newServingChain(s.T(), bus, testMux("GET /users", "HEAD /users/{id}", "OPTIONS /users",
		"POST "+barrierPath))
	token := accessToken(s.T(), map[string]interface{}{"sub": testUserID})

	serve(handler, newRequest(http.MethodGet, "/users", token, ""))
	serve(handler, newRequest(http.MethodHead, "/users/"+testUserID, token, ""))
	serve(handler, newRequest(http.MethodOptions, "/users", "", ""))

	s.expectOnlyTheBarrier(handler, events, token)
}

func (s *MiddlewareTestSuite) TestRoutesOutsideTheManagementAPIsPublishNothing() {
	excluded := []string{
		"/oauth2/token", "/flow/execute", "/.well-known/openid-configuration", "/auth/credentials/authenticate",
		"/register/passkey/start", "/access/evaluation", "/openid4vp/response", "/openid4vci/credential",
		"/design/resolve/flow", "/health/liveness", "/gate/signin", "/console/home", "/error/page", "/mcp",
		"/export", "/cimd/preview", "/users/me/update-credentials", "/scim/v2/Users/.search",
		"/oauth2/dcr/register",
	}
	patterns := make([]string, 0, len(excluded)+1)
	patterns = append(patterns, "POST "+barrierPath)
	for _, path := range excluded {
		patterns = append(patterns, "POST "+path)
	}
	bus, events := newAuditBus(s.T())
	handler := newServingChain(s.T(), bus, testMux(patterns...))
	token := accessToken(s.T(), map[string]interface{}{"sub": testUserID})

	for _, path := range excluded {
		serve(handler, newRequest(http.MethodPost, path, token, ""))
	}

	s.expectOnlyTheBarrier(handler, events, token)
}

// A prefix excludes a whole path segment, so a management family that shares its first letters is
// still audited.
func (s *MiddlewareTestSuite) TestAnExcludedPrefixDoesNotSwallowASimilarFamily() {
	bus, events := newAuditBus(s.T())
	handler := newServingChain(s.T(), bus, testMux("POST /flows", "POST /gateways", "POST /designs"))
	token := accessToken(s.T(), map[string]interface{}{"sub": testUserID})

	for _, tc := range []struct{ path, event, target string }{
		{"/flows", "flow.create", "flow"},
		{"/gateways", "gateway.create", "gateway"},
		{"/designs", EventManagementRequest, "designs"},
	} {
		serve(handler, newRequest(http.MethodPost, tc.path, token, ""))
		evt := awaitEvent(s.T(), events)
		s.Equal(tc.event, evt.env.Name)
		s.Equal(Ref{Type: tc.target}, evt.payload.Target())
	}
}

func (s *MiddlewareTestSuite) TestAnUnmatchedRoutePublishesNothing() {
	bus, events := newAuditBus(s.T())
	handler := newServingChain(s.T(), bus, testMux("POST "+barrierPath, "GET /users"))
	token := accessToken(s.T(), map[string]interface{}{"sub": testUserID})

	s.Equal(http.StatusNotFound, serve(handler, newRequest(http.MethodPost, "/no-such-route", token, "")).Code)
	s.Equal(http.StatusMethodNotAllowed, serve(handler, newRequest(http.MethodDelete, "/users", token, "")).Code)

	s.expectOnlyTheBarrier(handler, events, token)
}

func (s *MiddlewareTestSuite) TestTheClientIsThePeerAndNotAForwardedHeader() {
	bus, events := newAuditBus(s.T())
	handler := newServingChain(s.T(), bus, testMux("POST /users"))
	r := newRequest(http.MethodPost, "/users", accessToken(s.T(), map[string]interface{}{"sub": testUserID}), "")
	r.Header.Set("X-Forwarded-For", "203.0.113.7")
	r.Header.Set("X-Real-IP", "203.0.113.7")
	r.Header.Set("Forwarded", "for=203.0.113.7")
	r.Header.Set("User-Agent", strings.Repeat("ü", maxUserAgentLength+50))

	serve(handler, r)

	client := awaitEvent(s.T(), events).payload.Client()
	s.Equal(testClientIP, client.Address)
	s.Equal(strings.Repeat("ü", maxUserAgentLength), client.UserAgent)
}

func (s *MiddlewareTestSuite) TestAnInvalidTraceParentIsIgnored() {
	bus, events := newAuditBus(s.T())
	handler := newServingChain(s.T(), bus, testMux("POST /users"))
	token := accessToken(s.T(), map[string]interface{}{"sub": testUserID})

	for _, traceParent := range []string{
		"not-a-traceparent",
		"00-00000000000000000000000000000000-00f067aa0ba902b7-01",
		"00-4bf92f3577b34da6a3ce929d0e0e4736-0000000000000000-01",
	} {
		r := newRequest(http.MethodPost, "/users", token, "")
		r.Header.Set(constants.TraceParentHeaderName, traceParent)
		serve(handler, r)

		s.Empty(awaitEvent(s.T(), events).env.TraceParent, traceParent)
	}
}

func (s *MiddlewareTestSuite) TestTheEventIsPublishedAfterTheHandlerReturns() {
	bus, events := newAuditBus(s.T())
	mux := http.NewServeMux()
	mux.HandleFunc("POST /users", func(w http.ResponseWriter, _ *http.Request) {
		s.Empty(events, "the event was published before the change finished")
		w.WriteHeader(http.StatusCreated)
	})
	handler := newServingChain(s.T(), bus, mux)

	token := accessToken(s.T(), map[string]interface{}{"sub": testUserID})
	serve(handler, newRequest(http.MethodPost, "/users", token, ""))

	s.Equal(ActionCreate, awaitEvent(s.T(), events).payload.Action())
}

func (s *MiddlewareTestSuite) TestAFailedPublishLeavesTheResponseAlone() {
	bus := eventbusmock.NewEventBusInterfaceMock(s.T())
	bus.EXPECT().Publish(mock.Anything, mock.Anything).Return(errors.New("bus is shut down")).Once()
	handler := newServingChain(s.T(), bus, testMux("POST /users"))

	response := serve(handler, newRequest(http.MethodPost, "/users?status=201",
		accessToken(s.T(), map[string]interface{}{"sub": testUserID}), ""))

	s.Equal(http.StatusCreated, response.Code)
}

func (s *MiddlewareTestSuite) TestTheRecorderPassesFlushAndUnwrapThrough() {
	bus, events := newAuditBus(s.T())
	mux := http.NewServeMux()
	mux.HandleFunc("POST /users", func(w http.ResponseWriter, _ *http.Request) {
		s.Require().NoError(http.NewResponseController(w).Flush())
		_, err := w.Write([]byte("{}"))
		s.Require().NoError(err)
		w.WriteHeader(http.StatusInternalServerError)
	})
	handler := newServingChain(s.T(), bus, mux)

	response := serve(handler, newRequest(http.MethodPost, "/users",
		accessToken(s.T(), map[string]interface{}{"sub": testUserID}), ""))

	s.True(response.Flushed)
	s.Equal(OutcomeSucceeded, awaitEvent(s.T(), events).payload.Outcome(),
		"a status written after the body is not the status the client saw")
}

// publishingHandler answers with status after publishing, on bus, one user.create event per ID in
// userIDs, built from the request context as a service does.
func publishingHandler(bus eventbus.EventBusInterface, status int, userIDs ...string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		for _, id := range userIDs {
			target := Ref{Type: TargetTypeUser, ID: id}
			eventbus.TryPublish(ctx, bus, eventbus.NewEvent(ctx, EventUserCreate).
				With(NewPayload(ctx, target, ActionCreate, OutcomeSucceeded).WithSubject(target)))
		}
		w.WriteHeader(status)
	}
}

func (s *MiddlewareTestSuite) TestAServiceEventIsTheOnlyEventOfTheRequest() {
	bus, events := newAuditBus(s.T())
	mux := testMux("POST " + barrierPath)
	mux.HandleFunc("POST /users", publishingHandler(bus, http.StatusCreated, testUserID))
	handler := newServingChain(s.T(), bus, mux)
	token := accessToken(s.T(), map[string]interface{}{"sub": testUserID})

	s.Equal(http.StatusCreated, serve(handler, newRequest(http.MethodPost, "/users", token, "")).Code)

	evt := awaitEvent(s.T(), events)
	s.Equal(EventUserCreate, evt.env.Name)
	s.Equal(Ref{Type: TargetTypeUser, ID: testUserID}, evt.payload.Target())
	s.expectOnlyTheBarrier(handler, events, token)
}

func (s *MiddlewareTestSuite) TestEveryServiceEventOfARequestIsWrittenAndTheWrapperWritesNone() {
	bus, events := newAuditBus(s.T())
	mux := testMux("POST " + barrierPath)
	mux.HandleFunc("POST /users", publishingHandler(bus, http.StatusCreated, "u1", "u2"))
	handler := newServingChain(s.T(), bus, mux)
	token := accessToken(s.T(), map[string]interface{}{"sub": testUserID})

	serve(handler, newRequest(http.MethodPost, "/users", token, ""))

	s.Equal(Ref{Type: TargetTypeUser, ID: "u1"}, awaitEvent(s.T(), events).payload.Target())
	s.Equal(Ref{Type: TargetTypeUser, ID: "u2"}, awaitEvent(s.T(), events).payload.Target())
	s.expectOnlyTheBarrier(handler, events, token)
}

// An import changes more than the events of the services it reaches describe, so its own event is
// written beside theirs.
func (s *MiddlewareTestSuite) TestAnImportIsRecordedBesideTheServiceEventsOfItsChanges() {
	bus, events := newAuditBus(s.T())
	mux := testMux("POST " + barrierPath)
	mux.HandleFunc("POST /import", publishingHandler(bus, http.StatusOK, "u1", "u2"))
	mux.HandleFunc("POST /import/delete", publishingHandler(bus, http.StatusOK, "u3"))
	handler := newServingChain(s.T(), bus, mux)
	token := accessToken(s.T(), map[string]interface{}{"sub": testUserID})

	serve(handler, newRequest(http.MethodPost, "/import", token, ""))
	serve(handler, newRequest(http.MethodPost, "/import/delete", token, ""))

	for _, want := range []struct {
		name   string
		target Ref
	}{
		{EventUserCreate, Ref{Type: TargetTypeUser, ID: "u1"}},
		{EventUserCreate, Ref{Type: TargetTypeUser, ID: "u2"}},
		{"configuration.import", Ref{Type: "configuration"}},
		{EventUserCreate, Ref{Type: TargetTypeUser, ID: "u3"}},
		{"configuration.delete", Ref{Type: "configuration"}},
	} {
		evt := awaitEvent(s.T(), events)
		s.Equal(want.name, evt.env.Name)
		s.Equal(want.target, evt.payload.Target())
	}
	s.expectOnlyTheBarrier(handler, events, token)
}

// A payload built but never delivered still silences the wrapper: the failed publish is already logged.
func (s *MiddlewareTestSuite) TestAPayloadThatFailedToPublishStillSilencesTheWrapper() {
	bus := eventbusmock.NewEventBusInterfaceMock(s.T())
	bus.EXPECT().Publish(mock.Anything, mock.Anything).Return(errors.New("audit queue is full")).Once()
	mux := http.NewServeMux()
	mux.HandleFunc("POST /users", publishingHandler(bus, http.StatusCreated, testUserID))
	handler := newServingChain(s.T(), bus, mux)

	response := serve(handler, newRequest(http.MethodPost, "/users",
		accessToken(s.T(), map[string]interface{}{"sub": testUserID}), ""))

	s.Equal(http.StatusCreated, response.Code)
}

// A call that ends before any service builds a payload, as on invalid JSON, is recorded by the wrapper.
func (s *MiddlewareTestSuite) TestACallThatFailsBeforeAnyServiceIsRecordedByTheWrapper() {
	bus, events := newAuditBus(s.T())
	handler := newServingChain(s.T(), bus, testMux("POST /users", "POST "+barrierPath))
	token := accessToken(s.T(), map[string]interface{}{"sub": testUserID})

	s.Equal(http.StatusBadRequest,
		serve(handler, newRequest(http.MethodPost, "/users?status=400", token, "")).Code)

	evt := awaitEvent(s.T(), events)
	s.Equal(EventUserCreate, evt.env.Name)
	s.Equal(Ref{Type: TargetTypeUser}, evt.payload.Target())
	s.Equal(OutcomeFailed("invalid_request"), evt.payload.Outcome())
	s.expectOnlyTheBarrier(handler, events, token)
}

// A refused call never reaches the handler, so the rejection hook records it and nothing else does.
func (s *MiddlewareTestSuite) TestARefusedCallIsRecordedOnceByTheRejectionHook() {
	bus, events := newAuditBus(s.T())
	mux := testMux("POST " + barrierPath)
	mux.HandleFunc("POST /users", publishingHandler(bus, http.StatusCreated, testUserID))
	handler := newServingChain(s.T(), bus, mux)

	s.Equal(http.StatusUnauthorized, serve(handler, newRequest(http.MethodPost, "/users", "", "")).Code)

	evt := awaitEvent(s.T(), events)
	s.Equal(EventUserCreate, evt.env.Name)
	s.Equal(Ref{Type: TargetTypeUser}, evt.payload.Target())
	s.Equal(OutcomeDenied("unauthorized"), evt.payload.Outcome())
	s.expectOnlyTheBarrier(handler, events, accessToken(s.T(), map[string]interface{}{"sub": testUserID}))
}

// Each request has a marker of its own, so one request's service event never silences another's
// wrapper, whatever the interleaving.
func (s *MiddlewareTestSuite) TestConcurrentRequestsKeepTheirOwnMarker() {
	const requests = 20
	bus, events := newAuditBus(s.T())
	mux := testMux("POST /groups")
	mux.HandleFunc("POST /users", publishingHandler(bus, http.StatusCreated, testUserID))
	handler := newServingChain(s.T(), bus, mux)
	token := accessToken(s.T(), map[string]interface{}{"sub": testUserID})

	var wg sync.WaitGroup
	for i := range requests {
		path := "/users"
		if i%2 == 1 {
			path = "/groups"
		}
		wg.Go(func() { serve(handler, newRequest(http.MethodPost, path, token, "")) })
	}
	wg.Wait()

	names := map[string]int{}
	for range requests {
		names[awaitEvent(s.T(), events).env.Name]++
	}
	s.Equal(map[string]int{EventUserCreate: requests / 2, "group.create": requests / 2}, names)
}

func (s *MiddlewareTestSuite) TestANilBusIsRefused() {
	middleware, err := ManagementMiddleware(nil)

	s.ErrorIs(err, errNilBus)
	s.Nil(middleware)
}

func (s *MiddlewareTestSuite) TestTheRecorderUnwrapsToTheWrappedWriter() {
	inner := httptest.NewRecorder()
	recorder := &statusRecorder{ResponseWriter: inner, status: http.StatusOK}

	s.Same(inner, recorder.Unwrap())
}
