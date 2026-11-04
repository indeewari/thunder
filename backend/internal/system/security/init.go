// Copyright 2025-2026 The ThunderID Authors
// SPDX-License-Identifier: Apache-2.0

package security

import (
	"net/http"

	"github.com/thunder-id/thunderid/internal/system/jose/jwt"
)

// Initialize creates and returns the security middleware with necessary authenticators. The
// revocationEnforcer is consulted after authentication to reject revoked tokens; expectedAud, if
// non-empty, is the required audience.
//
// managementAPIKeyHash, when configured, admits a second mechanism for the import and variable
// store APIs only. It is registered ahead of the JWT authenticator because it claims a request only
// when the API-Key header hashes to that digest; anything else falls through to JWT unchanged.
//
// onRejection, when not nil, is told about every mutating request the middleware refuses on a path
// that is not public. Nil leaves the middleware as it would be without it.
func Initialize(jwtService jwt.JWTServiceInterface, revocationEnforcer RevocationEnforcerInterface,
	expectedAud string, managementAPIKeyHash string, onRejection RejectionHook,
) (func(http.Handler) http.Handler, error) {
	authenticators := make([]AuthenticatorInterface, 0, 2)

	if hasManagementAPIKey(managementAPIKeyHash) {
		managementAuthenticator, err := newManagementAPIKeyAuthenticator(
			managementAPIKeyHash, managementAPIKeyPaths)
		if err != nil {
			return nil, err
		}
		authenticators = append(authenticators, managementAuthenticator)
	}
	authenticators = append(authenticators, newJWTAuthenticator(jwtService, expectedAud))

	securityService, err := newSecurityService(
		authenticators, revocationEnforcer, publicPaths, apiPermissionEntries)
	if err != nil {
		return nil, err
	}
	securityService.onRejection = onRejection
	return middleware(securityService)
}
