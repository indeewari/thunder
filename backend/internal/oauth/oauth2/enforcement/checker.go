/*
 * Copyright (c) 2026, WSO2 LLC. (https://www.wso2.com).
 *
 * WSO2 LLC. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package enforcement

import (
	"context"
	"errors"

	syscontext "github.com/thunder-id/thunderid/internal/system/context"
	"github.com/thunder-id/thunderid/internal/system/log"
	"github.com/thunder-id/thunderid/internal/system/observability/event"
	"github.com/thunder-id/thunderid/pkg/thunderidengine/providers"
)

// ErrTokenRevoked indicates the presented token's JTI is on the deny list.
var ErrTokenRevoked = errors.New("token has been revoked")

// ErrEnforcementUnavailable indicates the deny list could not be consulted (operation DB
// unavailable or the circuit is open). Under the fail-closed policy callers MUST reject the token.
var ErrEnforcementUnavailable = errors.New("token revocation enforcement is unavailable")

// CheckerInterface enforces the single-token deny list on the AS hot path (introspection, refresh
// grant, token exchange) under a fail-closed policy: when the deny list cannot be consulted, tokens
// are rejected rather than allowed.
type CheckerInterface interface {
	// EnsureNotRevoked returns nil when the token identified by jti may proceed. It returns
	// ErrTokenRevoked when the jti is on the deny list, and ErrEnforcementUnavailable when the
	// deny list cannot be consulted (fail-closed). An empty jti is a no-op (nothing to enforce).
	EnsureNotRevoked(ctx context.Context, jti string) error
}

// checker is the default CheckerInterface. It consults the operation DB behind a circuit breaker
// and alerts (via an observability event) when the breaker trips.
type checker struct {
	store            RevokedTokenReaderInterface
	breaker          *circuitBreaker
	observabilitySvc providers.ObservabilityProvider
}

// NewChecker creates a deny-list checker backed by the operation DB, guarded by a circuit breaker
// and the fail-closed policy.
func NewChecker(observabilitySvc providers.ObservabilityProvider) CheckerInterface {
	return &checker{
		store:            newRevokedTokenReader(),
		breaker:          newCircuitBreaker(enforcementFailureThreshold, enforcementOpenDuration),
		observabilitySvc: observabilitySvc,
	}
}

// EnsureNotRevoked checks the deny list for the given jti, applying the circuit breaker and the
// fail-closed policy.
func (c *checker) EnsureNotRevoked(ctx context.Context, jti string) error {
	logger := log.GetLogger().With(log.String(log.LoggerKeyComponentName, "RevocationChecker"))

	if jti == "" {
		return nil
	}

	if !c.breaker.allow() {
		logger.Debug(ctx, "Operation DB circuit is open; failing closed for revocation check")
		return ErrEnforcementUnavailable
	}

	revoked, err := c.store.IsTokenRevoked(ctx, jti)
	if err != nil {
		logger.Error(ctx, "Failed to consult token revocation deny list; failing closed",
			log.Error(err))
		if c.breaker.recordFailure() {
			c.publishOperationDBUnavailableEvent(ctx, err)
		}
		return ErrEnforcementUnavailable
	}

	c.breaker.recordSuccess()
	if revoked {
		return ErrTokenRevoked
	}
	return nil
}

// publishOperationDBUnavailableEvent emits an alert event when the operation-DB circuit trips.
func (c *checker) publishOperationDBUnavailableEvent(ctx context.Context, cause error) {
	if c.observabilitySvc == nil || !c.observabilitySvc.IsEnabled() {
		return
	}

	evt := event.NewEvent(
		syscontext.GetTraceID(ctx),
		string(event.EventTypeOperationDBUnavailable),
		event.ComponentAuthHandler,
	).
		WithStatus(providers.StatusFailure).
		WithData("error", cause.Error())

	c.observabilitySvc.PublishEvent(ctx, evt)
}
