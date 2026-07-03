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
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestCircuitBreaker_StartsClosedAndAllows(t *testing.T) {
	cb := newCircuitBreaker(3, time.Minute)
	assert.True(t, cb.allow())
	assert.Equal(t, circuitClosed, cb.state)
}

func TestCircuitBreaker_StaysClosedBelowThreshold(t *testing.T) {
	cb := newCircuitBreaker(3, time.Minute)
	assert.False(t, cb.recordFailure())
	assert.False(t, cb.recordFailure())
	assert.True(t, cb.allow(), "circuit should remain closed below the failure threshold")
}

func TestCircuitBreaker_TripsAtThreshold(t *testing.T) {
	cb := newCircuitBreaker(3, time.Minute)
	assert.False(t, cb.recordFailure())
	assert.False(t, cb.recordFailure())
	assert.True(t, cb.recordFailure(), "third failure should trip the circuit open")
	assert.False(t, cb.allow(), "open circuit must short-circuit calls")
}

func TestCircuitBreaker_SuccessResetsFailureCount(t *testing.T) {
	cb := newCircuitBreaker(3, time.Minute)
	cb.recordFailure()
	cb.recordFailure()
	cb.recordSuccess()
	assert.False(t, cb.recordFailure())
	assert.False(t, cb.recordFailure())
	assert.True(t, cb.allow(), "success should have reset the consecutive-failure count")
}

func TestCircuitBreaker_HalfOpenAfterCooldownThenClose(t *testing.T) {
	cb := newCircuitBreaker(1, time.Minute)
	assert.True(t, cb.recordFailure())
	assert.False(t, cb.allow())

	// Simulate the cooldown window elapsing.
	cb.openedAt = time.Now().Add(-2 * time.Minute)

	assert.True(t, cb.allow(), "after cooldown a trial call is allowed (half-open)")
	assert.Equal(t, circuitHalfOpen, cb.state)

	cb.recordSuccess()
	assert.Equal(t, circuitClosed, cb.state)
	assert.True(t, cb.allow())
}

func TestCircuitBreaker_HalfOpenFailureReopens(t *testing.T) {
	cb := newCircuitBreaker(1, time.Minute)
	cb.recordFailure()
	cb.openedAt = time.Now().Add(-2 * time.Minute)

	assert.True(t, cb.allow())
	assert.Equal(t, circuitHalfOpen, cb.state)

	assert.True(t, cb.recordFailure(), "half-open failure should re-trip and report a fresh open transition")
	assert.False(t, cb.allow(), "circuit should be open again after a failed trial call")
}
