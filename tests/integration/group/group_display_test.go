// Copyright 2026 The ThunderID Authors
// SPDX-License-Identifier: Apache-2.0

package group

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"testing"

	"github.com/stretchr/testify/suite"

	"github.com/thunder-id/thunderid/tests/integration/testutils"
)

var displayTestOU = testutils.OrganizationUnit{
	Handle:      "group-display-test-ou",
	Name:        "Group Display Test OU",
	Description: "Organization unit for the group display attribute tests",
	Parent:      nil,
}

// GroupDisplayTestSuite covers the include=display variants of the group endpoints: the OU handle
// resolved onto listed groups, and the display name resolved for an application member. Both are
// skipped entirely when the caller does not ask for display attributes.
type GroupDisplayTestSuite struct {
	suite.Suite
	client  *http.Client
	ouID    string
	appID   string
	appName string
	groupID string
}

func TestGroupDisplayTestSuite(t *testing.T) {
	suite.Run(t, new(GroupDisplayTestSuite))
}

func (ts *GroupDisplayTestSuite) SetupSuite() {
	ts.client = testutils.GetHTTPClient()

	ouID, err := testutils.CreateOrganizationUnit(displayTestOU)
	ts.Require().NoError(err, "Failed to create the test organization unit")
	ts.ouID = ouID

	ts.appName = "Group Display Member App"
	appID, err := testutils.CreateApplication(testutils.Application{
		Name:         ts.appName,
		Description:  "Application that is a member of the display test group",
		OUID:         ts.ouID,
		ClientID:     "group_display_member_client",
		ClientSecret: "group_display_member_secret",
	})
	ts.Require().NoError(err, "Failed to create the member application")
	ts.appID = appID

	groupID, err := createGroup(CreateGroupRequest{
		Name:        "Group Display Test Group",
		Description: "Group used by the display attribute tests",
		OUID:        ts.ouID,
		Members: []Member{
			{Id: ts.appID, Type: MemberTypeApp},
		},
	})
	ts.Require().NoError(err, "Failed to create the test group")
	ts.groupID = groupID
}

func (ts *GroupDisplayTestSuite) TearDownSuite() {
	if ts.groupID != "" {
		if err := deleteGroup(ts.groupID); err != nil {
			ts.T().Logf("Failed to delete the test group during teardown: %v", err)
		}
	}
	if ts.appID != "" {
		if err := testutils.DeleteApplication(ts.appID); err != nil {
			ts.T().Logf("Failed to delete the member application during teardown: %v", err)
		}
	}
	if ts.ouID != "" {
		if err := testutils.DeleteOrganizationUnit(ts.ouID); err != nil {
			ts.T().Logf("Failed to delete the test organization unit during teardown: %v", err)
		}
	}
}

// --- helpers ---

func (ts *GroupDisplayTestSuite) get(path string) (int, []byte) {
	req, err := http.NewRequest(http.MethodGet, testServerURL+path, nil)
	ts.Require().NoError(err, "Failed to create the request for %s", path)

	resp, err := ts.client.Do(req)
	ts.Require().NoError(err, "Failed to send the request for %s", path)
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	ts.Require().NoError(err, "Failed to read the response for %s", path)
	return resp.StatusCode, body
}

func (ts *GroupDisplayTestSuite) listGroupsByOU(query string) *GroupListResponse {
	path := fmt.Sprintf("/groups/tree/%s", displayTestOU.Handle)
	if query != "" {
		path += "?" + query
	}
	status, body := ts.get(path)
	ts.Require().Equal(http.StatusOK, status, "Listing groups of an OU should return 200: %s", string(body))

	var list GroupListResponse
	ts.Require().NoError(json.Unmarshal(body, &list), "Failed to parse the group list: %s", string(body))
	return &list
}

func (ts *GroupDisplayTestSuite) findGroup(list *GroupListResponse) *GroupBasic {
	for i := range list.Groups {
		if list.Groups[i].Id == ts.groupID {
			return &list.Groups[i]
		}
	}
	return nil
}

func (ts *GroupDisplayTestSuite) listMembers(query string) *MemberListResponse {
	path := fmt.Sprintf("/groups/%s/members", ts.groupID)
	if query != "" {
		path += "?" + query
	}
	status, body := ts.get(path)
	ts.Require().Equal(http.StatusOK, status, "Listing group members should return 200: %s", string(body))

	var list MemberListResponse
	ts.Require().NoError(json.Unmarshal(body, &list), "Failed to parse the member list: %s", string(body))
	return &list
}

// --- tests ---

// TestGroupListByOUResolvesOUHandleWithDisplay asserts that the OU handle of a listed group is only
// resolved when display attributes are requested.
func (ts *GroupDisplayTestSuite) TestGroupListByOUResolvesOUHandleWithDisplay() {
	plain := ts.findGroup(ts.listGroupsByOU(""))
	ts.Require().NotNil(plain, "The test group must be listed under its organization unit")
	ts.Equal(ts.ouID, plain.OUID, "The listed group must report its organization unit id")
	ts.Empty(plain.OUHandle, "The OU handle must not be resolved without include=display")

	withDisplay := ts.findGroup(ts.listGroupsByOU("include=display"))
	ts.Require().NotNil(withDisplay, "The test group must be listed with display attributes")
	ts.Equal(displayTestOU.Handle, withDisplay.OUHandle,
		"include=display must resolve the handle of the group's organization unit")
}

// TestGroupListResolvesOUHandleWithDisplay asserts the same resolution on the global group list. The
// assertion is scoped to the groups the page happens to contain, because the list is shared with
// every other suite that created a group.
func (ts *GroupDisplayTestSuite) TestGroupListResolvesOUHandleWithDisplay() {
	status, body := ts.get("/groups?include=display&limit=100")
	ts.Require().Equal(http.StatusOK, status, "Listing groups should return 200: %s", string(body))

	var list GroupListResponse
	ts.Require().NoError(json.Unmarshal(body, &list), "Failed to parse the group list: %s", string(body))
	ts.Require().NotEmpty(list.Groups, "The group list must not be empty while this suite's group exists")

	for _, group := range list.Groups {
		if group.OUID != "" {
			ts.NotEmpty(group.OUHandle,
				"include=display must resolve the OU handle of every listed group with an OU")
		}
	}
}

// TestGroupMembersResolveApplicationDisplay asserts that an application member's display name is
// resolved from the application's name, and only when display attributes are requested.
func (ts *GroupDisplayTestSuite) TestGroupMembersResolveApplicationDisplay() {
	plain := ts.listMembers("")
	ts.Require().Len(plain.Members, 1, "The group must have exactly the application member it was created with")
	ts.Equal(ts.appID, plain.Members[0].Id, "The member must be the application")
	ts.Equal(MemberTypeApp, plain.Members[0].Type, "An application member is reported with the app type")
	ts.Empty(plain.Members[0].Display, "The display name must not be resolved without include=display")

	withDisplay := ts.listMembers("include=display")
	ts.Require().Len(withDisplay.Members, 1, "The member list must be unchanged by requesting display attributes")
	ts.Equal(ts.appName, withDisplay.Members[0].Display,
		"include=display must resolve an application member's display name from its name")
}
