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
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/suite"

	"github.com/thunder-id/thunderid/internal/system/config"

	"github.com/thunder-id/thunderid/tests/mocks/database/providermock"
)

const testDeploymentID = "test-deployment-id"

type RevokedTokenReaderTestSuite struct {
	suite.Suite
	mockdbProvider *providermock.DBProviderInterfaceMock
	mockDBClient   *providermock.DBClientInterfaceMock
	store          *revokedTokenReader
}

func TestRevokedTokenReaderTestSuite(t *testing.T) {
	suite.Run(t, new(RevokedTokenReaderTestSuite))
}

func (suite *RevokedTokenReaderTestSuite) SetupTest() {
	testConfig := &config.Config{
		Database: config.DatabaseConfig{
			Operation: config.DataSource{
				Type:   "sqlite",
				SQLite: config.SQLiteDataSource{Path: ":memory:"},
			},
		},
	}
	_ = config.InitializeServerRuntime("test", testConfig)

	suite.mockdbProvider = providermock.NewDBProviderInterfaceMock(suite.T())
	suite.mockDBClient = providermock.NewDBClientInterfaceMock(suite.T())

	suite.store = &revokedTokenReader{
		dbProvider:   suite.mockdbProvider,
		deploymentID: testDeploymentID,
	}
}

func (suite *RevokedTokenReaderTestSuite) TearDownTest() {
	config.ResetServerRuntime()
}

func (suite *RevokedTokenReaderTestSuite) TestNewRevokedTokenReader() {
	store := newRevokedTokenReader()
	assert.NotNil(suite.T(), store)
	assert.Implements(suite.T(), (*RevokedTokenReaderInterface)(nil), store)
}

func (suite *RevokedTokenReaderTestSuite) TestIsTokenRevoked_True() {
	suite.mockdbProvider.On("GetOperationDBClient").Return(suite.mockDBClient, nil)

	suite.mockDBClient.On("QueryContext", mock.Anything, queryIsTokenRevoked,
		"test-jti", mock.Anything, testDeploymentID).
		Return([]map[string]interface{}{{"1": 1}}, nil)

	revoked, err := suite.store.IsTokenRevoked(context.Background(), "test-jti")
	assert.NoError(suite.T(), err)
	assert.True(suite.T(), revoked)

	suite.mockDBClient.AssertExpectations(suite.T())
}

func (suite *RevokedTokenReaderTestSuite) TestIsTokenRevoked_False() {
	suite.mockdbProvider.On("GetOperationDBClient").Return(suite.mockDBClient, nil)

	suite.mockDBClient.On("QueryContext", mock.Anything, queryIsTokenRevoked,
		"test-jti", mock.Anything, testDeploymentID).
		Return([]map[string]interface{}{}, nil)

	revoked, err := suite.store.IsTokenRevoked(context.Background(), "test-jti")
	assert.NoError(suite.T(), err)
	assert.False(suite.T(), revoked)

	suite.mockDBClient.AssertExpectations(suite.T())
}

func (suite *RevokedTokenReaderTestSuite) TestIsTokenRevoked_DBClientError() {
	suite.mockdbProvider.On("GetOperationDBClient").Return(nil, errors.New("db client error"))

	revoked, err := suite.store.IsTokenRevoked(context.Background(), "test-jti")
	assert.Error(suite.T(), err)
	assert.False(suite.T(), revoked)

	suite.mockdbProvider.AssertExpectations(suite.T())
}

func (suite *RevokedTokenReaderTestSuite) TestIsTokenRevoked_QueryError() {
	suite.mockdbProvider.On("GetOperationDBClient").Return(suite.mockDBClient, nil)

	suite.mockDBClient.On("QueryContext", mock.Anything, queryIsTokenRevoked,
		"test-jti", mock.Anything, testDeploymentID).
		Return([]map[string]interface{}(nil), errors.New("query error"))

	revoked, err := suite.store.IsTokenRevoked(context.Background(), "test-jti")
	assert.Error(suite.T(), err)
	assert.False(suite.T(), revoked)
	assert.Contains(suite.T(), err.Error(), "error checking token revocation")

	suite.mockDBClient.AssertExpectations(suite.T())
}
