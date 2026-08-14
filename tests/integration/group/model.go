// Copyright 2025-2026 The ThunderID Authors
// SPDX-License-Identifier: Apache-2.0

package group

import (
	"encoding/json"

	"github.com/thunder-id/thunderid/tests/integration/testutils"
)

type I18nMessage struct {
	Key          string `json:"key,omitempty"`
	DefaultValue string `json:"defaultValue,omitempty"`
}

func (m *I18nMessage) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err == nil {
		m.DefaultValue = s
		return nil
	}
	type alias I18nMessage
	var a alias
	if err := json.Unmarshal(data, &a); err != nil {
		return err
	}
	*m = I18nMessage(a)
	return nil
}

const (
	testServerURL = "https://localhost:8095"
)

// MemberType represents the type of member entity.
type MemberType string

const (
	MemberTypeUser  MemberType = "user"
	MemberTypeGroup MemberType = "group"
	MemberTypeApp   MemberType = "app"
)

// Member represents a member of a group (a user, an application, or another group).
type Member struct {
	Id   string     `json:"id"`
	Type MemberType `json:"type"`
	// Display is only populated when the request asks for display attributes with include=display.
	Display string `json:"display,omitempty"`
}

// GroupBasic represents the basic information of a group.
type GroupBasic struct {
	Id          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
	OUID        string `json:"ouId"`
	// OUHandle is only populated when the request asks for display attributes with include=display.
	OUHandle string `json:"ouHandle,omitempty"`
}

// Group represents a complete group with members.
type Group struct {
	GroupBasic
	Members []Member `json:"members,omitempty"`
}

// CreateGroupRequest represents the request body for creating a group.
type CreateGroupRequest struct {
	Name        string   `json:"name"`
	Description string   `json:"description,omitempty"`
	OUID        string   `json:"ouId"`
	Members     []Member `json:"members,omitempty"`
}

// UpdateGroupRequest represents the request body for updating a group.
type UpdateGroupRequest struct {
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
	OUID        string `json:"ouId"`
}

// GroupListResponse represents the response for listing groups with pagination.
type GroupListResponse struct {
	TotalResults int              `json:"totalResults"`
	StartIndex   int              `json:"startIndex"`
	Count        int              `json:"count"`
	Groups       []GroupBasic     `json:"groups"`
	Links        []testutils.Link `json:"links"`
}

// MemberListResponse represents the response for listing group members with pagination.
type MemberListResponse struct {
	TotalResults int              `json:"totalResults"`
	StartIndex   int              `json:"startIndex"`
	Count        int              `json:"count"`
	Members      []Member         `json:"members"`
	Links        []testutils.Link `json:"links"`
}

// CreateGroupByPathRequest represents the request body for creating a group under a specific OU path.
type CreateGroupByPathRequest struct {
	Name        string   `json:"name"`
	Description string   `json:"description,omitempty"`
	Members     []Member `json:"members,omitempty"`
}

// MembersRequest represents the request body for adding or removing members from a group.
type MembersRequest struct {
	Members []Member `json:"members"`
}

// ErrorResponse represents an error response.
type ErrorResponse struct {
	Code        string      `json:"code"`
	Message     I18nMessage `json:"message"`
	Description I18nMessage `json:"description,omitempty"`
}
