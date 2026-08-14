// Copyright 2026 The ThunderID Authors
// SPDX-License-Identifier: Apache-2.0

package execution

import (
	"fmt"
	"net/http"
	"testing"

	"github.com/stretchr/testify/suite"
	"github.com/thunder-id/thunderid/tests/integration/flow/common"
	"github.com/thunder-id/thunderid/tests/integration/testutils"
)

// errCodeMaxCallDepth is returned when nested CALL nodes exceed the engine's frame limit.
const errCodeMaxCallDepth = "FES-1013"

// callChainLength is one longer than the engine's maximum call depth, so executing the head of the
// chain is guaranteed to cross the limit. The engine's limit is 10 frames.
const callChainLength = 12

var callDepthTestOU = testutils.OrganizationUnit{
	Handle:      "call_depth_test_ou",
	Name:        "Test OU for Call Depth",
	Description: "Organization unit created for call depth testing",
	Parent:      nil,
}

type CallDepthTestSuite struct {
	suite.Suite
	ouID      string
	appID     string
	flowIDs   []string
	headFlow  string
	userType  string
	entityTyp string
}

func TestCallDepthTestSuite(t *testing.T) {
	suite.Run(t, new(CallDepthTestSuite))
}

// SetupSuite builds a chain of authentication flows where each one calls the next, then binds an
// application to the head of the chain. The chain is built from the tail backwards because a CALL
// node must reference a flow that already exists.
func (ts *CallDepthTestSuite) SetupSuite() {
	ouID, err := testutils.CreateOrganizationUnit(callDepthTestOU)
	ts.Require().NoError(err, "Failed to create test organization unit")
	ts.ouID = ouID

	// The tail is a plain authentication flow that calls nothing.
	tailID, err := testutils.CreateFlow(ts.buildLeafFlow())
	ts.Require().NoError(err, "Failed to create leaf flow")
	ts.flowIDs = append(ts.flowIDs, tailID)

	next := tailID
	for i := 0; i < callChainLength; i++ {
		flowID, err := testutils.CreateFlow(ts.buildCallingFlow(i, next))
		ts.Require().NoError(err, "Failed to create calling flow %d", i)
		ts.flowIDs = append(ts.flowIDs, flowID)
		next = flowID
	}
	ts.headFlow = next

	app := testutils.Application{
		Name:         "Call Depth Test Application",
		Description:  "Application bound to a deeply nested call chain",
		ClientID:     "call_depth_test_client",
		ClientSecret: "call_depth_test_secret", //nolint:gosec // test credential
		RedirectURIs: []string{"http://localhost:3000/callback"},
		OUID:         ts.ouID,
		AuthFlowID:   ts.headFlow,
	}
	appID, err := testutils.CreateApplication(app)
	ts.Require().NoError(err, "Failed to create test application")
	ts.appID = appID
}

func (ts *CallDepthTestSuite) TearDownSuite() {
	if ts.appID != "" {
		if err := testutils.DeleteApplication(ts.appID); err != nil {
			ts.T().Logf("Failed to delete test application during teardown: %v", err)
		}
	}
	// Delete from the head backwards so a flow is never removed while another still references it.
	for i := len(ts.flowIDs) - 1; i >= 0; i-- {
		if err := testutils.DeleteFlow(ts.flowIDs[i]); err != nil {
			ts.T().Logf("Failed to delete flow %s during teardown: %v", ts.flowIDs[i], err)
		}
	}
	if ts.ouID != "" {
		if err := testutils.DeleteOrganizationUnit(ts.ouID); err != nil {
			ts.T().Logf("Failed to delete test organization unit during teardown: %v", err)
		}
	}
}

// buildLeafFlow returns the flow at the end of the chain, which calls nothing.
func (ts *CallDepthTestSuite) buildLeafFlow() testutils.Flow {
	return testutils.Flow{
		Name:     "Call Depth Leaf Flow",
		FlowType: "AUTHENTICATION",
		Handle:   "auth_flow_call_depth_leaf",
		Nodes: []map[string]interface{}{
			{"id": "start", "type": "START", "onSuccess": "auth_assert"},
			{
				"id":        "auth_assert",
				"type":      "TASK_EXECUTION",
				"executor":  map[string]interface{}{"name": "AuthAssertExecutor"},
				"onSuccess": "end",
			},
			{"id": "end", "type": "END"},
		},
	}
}

// buildCallingFlow returns a flow whose only work is to call the given target flow.
func (ts *CallDepthTestSuite) buildCallingFlow(index int, targetFlowID string) testutils.Flow {
	return testutils.Flow{
		Name:     fmt.Sprintf("Call Depth Link %d Flow", index),
		FlowType: "AUTHENTICATION",
		Handle:   fmt.Sprintf("auth_flow_call_depth_link_%d", index),
		Nodes: []map[string]interface{}{
			{"id": "start", "type": "START", "onSuccess": "call_next"},
			{
				"id":        "call_next",
				"type":      "CALL",
				"flow":      map[string]interface{}{"ref": targetFlowID},
				"onSuccess": "auth_assert",
			},
			{
				"id":        "auth_assert",
				"type":      "TASK_EXECUTION",
				"executor":  map[string]interface{}{"name": "AuthAssertExecutor"},
				"onSuccess": "end",
			},
			{"id": "end", "type": "END"},
		},
	}
}

// A chain of nested CALL nodes deeper than the engine allows must be refused rather than recursing
// until the process runs out of stack. The limit is what stops a mutually recursive set of flows,
// which the flow designer does not prevent an operator from authoring, from taking the server down.
func (ts *CallDepthTestSuite) TestExecute_ExceedingCallDepthRejected() {
	step, err := common.InitiateAuthenticationFlow(ts.appID, false, nil, "")

	// The engine may refuse the request outright or surface the failure on the step, depending on how
	// far the chain unwinds before the limit trips. Either is acceptable; recursing without a limit is
	// not.
	if err != nil {
		ts.Contains(err.Error(), fmt.Sprintf("%d", http.StatusBadRequest),
			"a call chain past the depth limit should be rejected as a client error: %v", err)
		return
	}

	ts.Require().NotNil(step, "expected a flow step for a rejected call chain")
	ts.NotEqual("COMPLETE", step.FlowStatus,
		"a call chain past the depth limit must not complete")
	if step.Error != nil {
		ts.Equal(errCodeMaxCallDepth, step.Error.Code,
			"the failure should name the call depth limit")
	}
}
