// Copyright 2026 The ThunderID Authors
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/thunder-id/thunderid/internal/system/config"
	"github.com/thunder-id/thunderid/internal/system/constants"
	"github.com/thunder-id/thunderid/internal/system/cryptolib"
	"github.com/thunder-id/thunderid/internal/system/eventbus"
	"github.com/thunder-id/thunderid/internal/system/jose/jwt"
	"github.com/thunder-id/thunderid/internal/system/middleware"
	"github.com/thunder-id/thunderid/internal/system/revocationcache"
	"github.com/thunder-id/thunderid/internal/system/security"
	engineconfig "github.com/thunder-id/thunderid/pkg/thunderidengine/config"
	"github.com/thunder-id/thunderid/tests/mocks/eventbusmock"
	"github.com/thunder-id/thunderid/tests/mocks/jose/jwtmock"
)

const (
	testSource       = "server"
	testInstanceID   = "test-instance"
	testDeploymentID = "test-deployment"
	testIssuer       = "https://audit.test"
	testAPIKey       = "pat-0123456789abcdef"
	testRemoteAddr   = "192.0.2.10:52814"
	testClientIP     = "192.0.2.10"
	testUserAgent    = "audit-test/1.0"
	testUserID       = "01900000-0000-7000-8000-000000000030"
	testAppID        = "01900000-0000-7000-8000-000000000031"
	testAgentID      = "01900000-0000-7000-8000-000000000032"
	// testStatusParam names the query parameter the test routes answer with as their status.
	testStatusParam = "status"
	eventWait       = 3 * time.Second
)

// received is one audit event a subscriber was handed.
type received struct {
	env     eventbus.Envelope
	payload Payload
}

// newAuditBus builds a bus with the audit catalog and subscribes a sink that forwards every event it
// receives to the returned channel.
func newAuditBus(t *testing.T) (eventbus.EventBusInterface, <-chan received) {
	t.Helper()
	bus, stopper, err := eventbus.Initialize(eventbus.Config{
		Source:             testSource,
		InstanceID:         testInstanceID,
		Catalog:            Catalog(),
		RejectUnregistered: true,
	})
	require.NoError(t, err)
	t.Cleanup(stopper.Stop)

	events := make(chan received, 32)
	sink := eventbusmock.NewSubscriberMock[Payload](t)
	sink.EXPECT().Handle(mock.Anything, mock.Anything, mock.Anything).
		RunAndReturn(func(_ context.Context, env eventbus.Envelope, payload Payload) error {
			events <- received{env: env, payload: payload}
			return nil
		}).Maybe()
	require.NoError(t, Subscribe(bus, "test-sink", sink))
	return bus, events
}

// awaitEvent returns the next event the sink received.
func awaitEvent(t *testing.T, events <-chan received) received {
	t.Helper()
	select {
	case evt := <-events:
		return evt
	case <-time.After(eventWait):
		t.Fatal("no audit event was delivered")
		return received{}
	}
}

// withServerRuntime initializes the server runtime the security layer and deployment resolution
// read, for the duration of the test.
func withServerRuntime(t *testing.T) {
	t.Helper()
	config.ResetServerRuntime()
	cfg := &config.Config{
		Server: engineconfig.ServerConfig{Identifier: testDeploymentID},
		JWT:    engineconfig.JWTConfig{Issuer: testIssuer},
	}
	require.NoError(t, config.InitializeServerRuntime("", cfg))
	t.Cleanup(config.ResetServerRuntime)
}

// newServingChain puts mux behind the layers the server binary puts in front of it, outermost first:
// correlation, audit context, deployment, security with the rejection hook, and the management
// middleware.
func newServingChain(t *testing.T, bus eventbus.EventBusInterface, mux http.Handler) http.Handler {
	t.Helper()
	withServerRuntime(t)
	security.InitSystemPermissions("")

	jwtService := jwtmock.NewJWTServiceInterfaceMock(t)
	jwtService.EXPECT().VerifyJWT(mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(nil).Maybe()
	enforcer, _, err := revocationcache.Initialize(revocationcache.Config{})
	require.NoError(t, err)
	rejection, err := RejectionHook(bus)
	require.NoError(t, err)
	secure, err := security.Initialize(jwtService, enforcer, "", cryptolib.HashToken(testAPIKey), rejection)
	require.NoError(t, err)

	management, err := ManagementMiddleware(bus)
	require.NoError(t, err)

	handler := secure(management(mux))
	handler = middleware.DeploymentIDMiddleware(handler)
	handler = ContextMiddleware(handler)
	return middleware.CorrelationIDMiddleware(handler)
}

// testMux serves every route with the status named by the status query parameter, 200 by default.
func testMux(patterns ...string) *http.ServeMux {
	mux := http.NewServeMux()
	for _, pattern := range patterns {
		mux.HandleFunc(pattern, answerWithStatus)
	}
	return mux
}

// answerWithStatus writes the status the request asks for.
func answerWithStatus(w http.ResponseWriter, r *http.Request) {
	status, err := strconv.Atoi(r.URL.Query().Get(testStatusParam))
	if err != nil {
		status = http.StatusOK
	}
	w.WriteHeader(status)
}

// accessToken builds a compact access token carrying claims, as this server issues them. The
// signature is not checked: the JWT service mock accepts every token.
func accessToken(t *testing.T, claims map[string]interface{}) string {
	t.Helper()
	claims["iss"] = testIssuer
	if _, ok := claims["scope"]; !ok {
		claims["scope"] = "system"
	}
	header, err := json.Marshal(map[string]string{"alg": "RS256", "typ": jwt.TokenTypeAccessToken})
	require.NoError(t, err)
	payload, err := json.Marshal(claims)
	require.NoError(t, err)
	encode := base64.RawURLEncoding.EncodeToString
	return encode(header) + "." + encode(payload) + "." + encode([]byte("signature"))
}

// newRequest builds a request from the test client address with the given credentials.
func newRequest(method, target, bearer, apiKey string) *http.Request {
	r := httptest.NewRequest(method, target, nil)
	r.RemoteAddr = testRemoteAddr
	r.Header.Set("User-Agent", testUserAgent)
	if bearer != "" {
		r.Header.Set(constants.AuthorizationHeaderName, constants.AuthSchemeBearer+bearer)
	}
	if apiKey != "" {
		r.Header.Set(constants.APIKeyHeaderName, apiKey)
	}
	return r
}

// securedContext returns the context the security layer hands down for a request with the given
// credentials, built by the real authenticators.
func securedContext(t *testing.T, bearer, apiKey string) context.Context {
	t.Helper()
	withServerRuntime(t)
	security.InitSystemPermissions("")

	jwtService := jwtmock.NewJWTServiceInterfaceMock(t)
	jwtService.EXPECT().VerifyJWT(mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(nil).Maybe()
	enforcer, _, err := revocationcache.Initialize(revocationcache.Config{})
	require.NoError(t, err)
	secure, err := security.Initialize(jwtService, enforcer, "", cryptolib.HashToken(testAPIKey), nil)
	require.NoError(t, err)

	var ctx context.Context
	handler := secure(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) { ctx = r.Context() }))
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, newRequest(http.MethodPut, "/variables/API_URL", bearer, apiKey))
	require.NotNil(t, ctx, "the security layer refused the request with %d", recorder.Code)
	return ctx
}
