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

// Package enforcement provides the read/enforcement path for the single-token deny list (the JTI
// deny list) backed by the database.operation classification. It rejects revoked tokens on the AS
// hot path (introspection, refresh grant, token exchange) under a fail-closed policy. The write
// path (RFC 7009 endpoint) lives in the revocation package; this package holds no write symbol, so
// the hot-path consumers that import it cannot revoke tokens, only check them.
package enforcement

import (
	"context"
	"fmt"
	"time"

	"github.com/thunder-id/thunderid/internal/system/config"
	"github.com/thunder-id/thunderid/internal/system/database/provider"
)

// RevokedTokenReaderInterface defines the deny-list read path for single-token revocation. It is
// read-only by construction, kept separate from the revocation write path so that the AS hot path
// cannot revoke tokens, only check them.
type RevokedTokenReaderInterface interface {
	// IsTokenRevoked reports whether a non-expired deny-list entry exists for the given JTI.
	IsTokenRevoked(ctx context.Context, jti string) (bool, error)
}

// revokedTokenReader implements RevokedTokenReaderInterface against the operation database.
type revokedTokenReader struct {
	dbProvider   provider.DBProviderInterface
	deploymentID string
}

// newRevokedTokenReader creates a new revokedTokenReader.
func newRevokedTokenReader() RevokedTokenReaderInterface {
	return &revokedTokenReader{
		dbProvider:   provider.GetDBProvider(),
		deploymentID: config.GetServerRuntime().Config.Server.Identifier,
	}
}

// IsTokenRevoked reports whether a non-expired deny-list entry exists for the given JTI.
func (s *revokedTokenReader) IsTokenRevoked(ctx context.Context, jti string) (bool, error) {
	dbClient, err := s.dbProvider.GetOperationDBClient()
	if err != nil {
		return false, fmt.Errorf("failed to get operation database client: %w", err)
	}

	results, err := dbClient.QueryContext(ctx, queryIsTokenRevoked, jti, time.Now().UTC(), s.deploymentID)
	if err != nil {
		return false, fmt.Errorf("error checking token revocation: %w", err)
	}

	return len(results) > 0, nil
}
