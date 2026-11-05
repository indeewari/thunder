// Copyright 2026 The ThunderID Authors
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/suite"

	"github.com/thunder-id/thunderid/tests/integration/testutils"
)

const (
	auditConfigKey = "audit"
	logConfigKey   = "log"

	correlationIDHeader = "X-Correlation-ID"
	deniedResult        = "denied"

	// exitTimeout bounds how long a server with an invalid audit configuration may take to refuse it.
	exitTimeout = 60 * time.Second
	// quietPeriod is how long a suite waits for an audit line that must not be written.
	quietPeriod = 2 * time.Second
)

// lineTimePattern is the time format of an audit line: UTC with exactly six fractional digits.
var lineTimePattern = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}Z$`)

// AuditLogTestSuite drives management calls against a running server and reads the audit lines it
// writes to standard output. The server writes its output to the server log only when this test
// process starts it, so the suite restarts it first, and every scenario that changes the
// configuration restores it before the next one.
type AuditLogTestSuite struct {
	suite.Suite
	reader         *testutils.AuditLogReader
	originalAudit  interface{}
	originalLog    interface{}
	configModified bool
	// prefix namespaces every variable this run creates, so a leftover from an earlier run is invisible.
	prefix string
}

func TestAuditLogTestSuite(t *testing.T) {
	suite.Run(t, new(AuditLogTestSuite))
}

func (ts *AuditLogTestSuite) SetupSuite() {
	ts.prefix = fmt.Sprintf("AUDIT_%d_", time.Now().UnixNano())

	originalAudit, err := testutils.ReadDeploymentConfigKey(auditConfigKey)
	ts.Require().NoError(err, "failed to read the audit config")
	ts.originalAudit = originalAudit
	originalLog, err := testutils.ReadDeploymentConfigKey(logConfigKey)
	ts.Require().NoError(err, "failed to read the log config")
	ts.originalLog = originalLog

	ts.Require().NoError(testutils.RestartServer(), "failed to restart the server so its output is captured")
	ts.Require().NoError(testutils.ObtainAdminAccessToken(), "failed to re-obtain the admin token after restart")
	ts.reader = testutils.NewAuditLogReader()
}

// SetupTest puts back the configuration a previous scenario changed.
func (ts *AuditLogTestSuite) SetupTest() {
	if ts.configModified {
		ts.restartWith(ts.originalAudit, ts.originalLog)
		ts.configModified = false
	}
	ts.Require().NoError(ts.reader.Reset())
}

// TearDownSuite restores the configuration read in SetupSuite. A missing key is written back as null,
// which the server treats the same as an absent key.
func (ts *AuditLogTestSuite) TearDownSuite() {
	if !ts.configModified {
		return
	}
	ts.Assert().NoError(testutils.PatchDeploymentConfig(map[string]interface{}{
		auditConfigKey: ts.originalAudit,
		logConfigKey:   ts.originalLog,
	}), "teardown: failed to restore the audit and log config")
	ts.Assert().NoError(testutils.RestartServer(), "teardown: server did not restart after the config restore")
	ts.Assert().NoError(testutils.ObtainAdminAccessToken(), "teardown: failed to re-obtain the admin token")
}

// With the shipped configuration a mutating management call writes one audit line named for the
// resource and the action attempted, with the admin, the variable and the trace ID of the response, and
// reads and protocol calls write none. A PUT that creates the variable is recorded as a create.
func (ts *AuditLogTestSuite) TestAMutatingManagementCallWritesOneAuditLine() {
	name := ts.prefix + "DEFAULT"

	created := ts.send(http.MethodPut, "/variables/"+name, `{"value":"audited"}`)
	ts.Require().Equal(http.StatusCreated, created.StatusCode)
	ts.Equal(http.StatusOK, ts.send(http.MethodGet, "/variables/"+name, "").StatusCode)
	ts.Equal(http.StatusUnauthorized, ts.tokenRequestWithAnUnknownClient())
	deleted := ts.send(http.MethodDelete, "/variables/"+name, "")
	ts.Require().Equal(http.StatusNoContent, deleted.StatusCode)

	deleteLine, err := ts.reader.Await(func(line testutils.AuditLine) bool {
		return line.Target.ID == name && line.Action == "delete"
	})
	ts.Require().NoError(err, "the delete wrote no audit line")
	lines, err := ts.reader.Read()
	ts.Require().NoError(err)

	var forVariable []testutils.AuditLine
	for _, line := range lines {
		ts.NotEqual("oauth2", line.Target.Type, "a protocol call wrote an audit line")
		if line.Target.ID == name {
			forVariable = append(forVariable, line)
		}
	}
	ts.Require().Len(forVariable, 2, "one line for the put and one for the delete, none for the read")

	putLine := forVariable[0]
	ts.True(strings.HasPrefix(putLine.Raw, `{"log_type":"AUDIT","schema_version":1,`), putLine.Raw)
	ts.Equal("variable.create", putLine.Event)
	ts.Equal("create", putLine.Action)
	ts.Equal("variable.delete", deleteLine.Event)
	ts.Equal("server", putLine.Source)
	ts.Regexp(lineTimePattern, putLine.Time)
	ts.NotEmpty(putLine.ID)
	ts.NotEmpty(putLine.BootID)
	ts.NotEmpty(putLine.InstanceID)
	ts.Equal("user", putLine.Actor.Type)
	ts.NotEmpty(putLine.Actor.ID)
	ts.Equal(testutils.AuditRef{Type: "variable", ID: name}, putLine.Target)
	ts.Equal(map[string]string{"result": "succeeded"}, putLine.Outcome)
	ts.Contains([]string{"127.0.0.1", "::1"}, putLine.Client["address"])
	ts.Equal(created.Header.Get(correlationIDHeader), putLine.TraceID)
	ts.Equal(deleted.Header.Get(correlationIDHeader), deleteLine.TraceID)
	ts.Equal(putLine.BootID, deleteLine.BootID)
	ts.Greater(deleteLine.Seq, putLine.Seq)
	ts.NotContains(putLine.Raw, "audited", "the request body is never recorded")

	ts.Contains(ts.accessLogLine(putLine.TraceID), "/variables/"+name,
		"the access log line of the request carries the same trace ID")
}

// A mutating call without credentials, or by a caller without the permission, is refused by the
// security layer and recorded under the event of its route with a denied outcome: anonymously without
// credentials, and for the verified user without the permission.
func (ts *AuditLogTestSuite) TestARefusedMutatingCallIsRecordedAsDenied() {
	name := ts.prefix + "REFUSED"

	anonymous := ts.sendWith(testutils.GetRawHTTPClient(), http.MethodPut, "/variables/"+name, `{"value":"x"}`)
	ts.Require().Equal(http.StatusUnauthorized, anonymous.StatusCode)
	unauthorized := ts.awaitDenied(anonymous.Header.Get(correlationIDHeader))
	ts.Equal("variable.update", unauthorized.Event, "a refused attempt keeps the name of the route")
	ts.Equal(testutils.AuditRef{Type: "anonymous"}, unauthorized.Actor)
	ts.Equal(testutils.AuditRef{Type: "variable"}, unauthorized.Target)
	ts.Equal("update", unauthorized.Action, "a refused PUT cannot know it would have created")
	ts.Equal(map[string]string{"result": "denied", "reason": "unauthorized"}, unauthorized.Outcome)

	userID, client := ts.createUserWithoutPermissions()
	unprivileged := ts.sendWith(client, http.MethodDelete, "/variables/"+name, "")
	ts.Require().Equal(http.StatusForbidden, unprivileged.StatusCode)
	forbidden := ts.awaitDenied(unprivileged.Header.Get(correlationIDHeader))
	ts.Equal("variable.delete", forbidden.Event)
	ts.Equal(testutils.AuditRef{Type: "user", ID: userID}, forbidden.Actor)
	ts.Equal(testutils.AuditRef{Type: "variable"}, forbidden.Target)
	ts.Equal("delete", forbidden.Action)
	ts.Equal(map[string]string{"result": "denied", "reason": "forbidden"}, forbidden.Outcome)
}

// Creating, updating and deleting a user through the management API writes one line each, published by
// the user service with the user as target and subject, and no second line from the management wrapper.
// The password the user is created with appears in no line.
func (ts *AuditLogTestSuite) TestAUserLifecycleWritesOneLinePerChange() {
	ouID, userType := ts.createUserType("lifecycle")
	adminID := ts.adminUserID()
	username := strings.ToLower(ts.prefix) + "lifecycle"
	password := "AuditLifecycle123!"

	created, body := ts.exchange(testutils.GetHTTPClient(), http.MethodPost, "/users", fmt.Sprintf(
		`{"ouId":%q,"type":%q,"attributes":{"username":%q,"password":%q}}`, ouID, userType, username, password))
	ts.Require().Equal(http.StatusCreated, created.StatusCode, string(body))
	var user testutils.User
	ts.Require().NoError(json.Unmarshal(body, &user))
	ts.Require().NotEmpty(user.ID)
	ts.T().Cleanup(func() { _ = testutils.DeleteUser(user.ID) })
	updated := ts.send(http.MethodPut, "/users/"+user.ID, fmt.Sprintf(
		`{"ouId":%q,"type":%q,"attributes":{"username":%q}}`, ouID, userType, username+"-renamed"))
	ts.Require().Equal(http.StatusOK, updated.StatusCode)
	deleted := ts.send(http.MethodDelete, "/users/"+user.ID, "")
	ts.Require().Equal(http.StatusNoContent, deleted.StatusCode)

	userRef := testutils.AuditRef{Type: "user", ID: user.ID}
	for _, tc := range []struct {
		response *http.Response
		event    string
		action   string
	}{
		{created, "user.create", "create"},
		{updated, "user.update", "update"},
		{deleted, "user.delete", "delete"},
	} {
		line := ts.onlyLineOf(tc.response)
		ts.Equal(tc.event, line.Event)
		ts.Equal(tc.action, line.Action)
		ts.Equal(userRef, line.Target, tc.event)
		ts.Equal(userRef, line.Subject, tc.event)
		ts.Equal(testutils.AuditRef{Type: "user", ID: adminID}, line.Actor, tc.event)
		ts.Equal(map[string]string{"result": "succeeded"}, line.Outcome, tc.event)
		ts.NotContains(line.Raw, password, "a credential is never recorded")
		ts.NotContains(line.Raw, `"details"`, "a user event carries no details")
	}
}

// An update of a user that does not exist reaches the user service, which records the failed attempt.
func (ts *AuditLogTestSuite) TestAnUpdateOfAMissingUserIsRecordedAsFailed() {
	missing := unusedUserID()
	ouID, userType := ts.createUserType("missing")

	updated := ts.send(http.MethodPut, "/users/"+missing, fmt.Sprintf(
		`{"ouId":%q,"type":%q,"attributes":{"username":"nobody"}}`, ouID, userType))
	ts.Require().Equal(http.StatusNotFound, updated.StatusCode)

	line := ts.onlyLineOf(updated)
	ts.Equal("user.update", line.Event)
	ts.Equal(testutils.AuditRef{Type: "user", ID: missing}, line.Target)
	ts.Equal(testutils.AuditRef{}, line.Subject, "a user that was not changed is not the subject")
	ts.Equal(map[string]string{"result": "failed", "reason": "usr_1003"}, line.Outcome)
}

// An import that creates a user writes the user service's event for the user and the import's own line,
// and the lookup that decides between update and create writes nothing.
func (ts *AuditLogTestSuite) TestAnImportWritesItsUserEventsAndItsOwnLine() {
	ouID, userType := ts.createUserType("import")
	userID := unusedUserID()
	username := strings.ToLower(ts.prefix) + "imported"
	password := "AuditImport123!"
	request, err := json.Marshal(testutils.ImportRequest{
		Content: fmt.Sprintf("resource_type: user\nid: %s\ntype: %s\nouId: %s\nattributes:\n  username: %s\n"+
			"credentials:\n  password: %s\n", userID, userType, ouID, username, password),
		Options: testutils.ImportOptions{Upsert: true, ContinueOnError: true, Target: "runtime"},
	})
	ts.Require().NoError(err)

	imported, body := ts.exchange(testutils.GetHTTPClient(), http.MethodPost, "/import", string(request))
	ts.Require().Equal(http.StatusOK, imported.StatusCode, string(body))
	ts.T().Cleanup(func() { _ = testutils.DeleteUser(userID) })
	var result testutils.ImportResponse
	ts.Require().NoError(json.Unmarshal(body, &result))
	ts.Require().Equal(1, result.Summary.Imported, string(body))

	lines := ts.linesOf(imported, 2)
	userRef := testutils.AuditRef{Type: "user", ID: userID}
	ts.Equal("user.create", lines[0].Event)
	ts.Equal(userRef, lines[0].Target)
	ts.Equal(userRef, lines[0].Subject)
	ts.Equal(map[string]string{"result": "succeeded"}, lines[0].Outcome)
	ts.Equal("configuration.import", lines[1].Event)
	ts.Equal(testutils.AuditRef{Type: "configuration"}, lines[1].Target)
	ts.Equal(map[string]string{"result": "succeeded"}, lines[1].Outcome)
	for _, line := range lines {
		ts.NotContains(line.Raw, password, "a credential is never recorded")
	}
}

// A create the handler rejects as invalid JSON never reaches the user service, so the management wrapper
// records it under the same name, failed, and without an ID.
func (ts *AuditLogTestSuite) TestAUserCreateWithInvalidJSONIsRecordedByTheWrapper() {
	rejected := ts.send(http.MethodPost, "/users", `{"ouId":`)
	ts.Require().Equal(http.StatusBadRequest, rejected.StatusCode)

	line := ts.onlyLineOf(rejected)
	ts.Equal("user.create", line.Event)
	ts.Equal(testutils.AuditRef{Type: "user"}, line.Target)
	ts.Equal(testutils.AuditRef{}, line.Subject)
	ts.Equal(map[string]string{"result": "failed", "reason": "invalid_request"}, line.Outcome)
}

// A create without a token never reaches the routes, so the security layer's rejection hook records it,
// once.
func (ts *AuditLogTestSuite) TestARefusedUserCreateIsRecordedOnceByTheRejectionHook() {
	refused := ts.sendWith(testutils.GetRawHTTPClient(), http.MethodPost, "/users", `{"ouId":"x"}`)
	ts.Require().Equal(http.StatusUnauthorized, refused.StatusCode)

	line := ts.onlyLineOf(refused)
	ts.Equal("user.create", line.Event)
	ts.Equal(testutils.AuditRef{Type: "anonymous"}, line.Actor)
	ts.Equal(testutils.AuditRef{Type: "user"}, line.Target)
	ts.Equal(map[string]string{"result": "denied", "reason": "unauthorized"}, line.Outcome)
}

// A read the security layer refuses is not recorded.
func (ts *AuditLogTestSuite) TestARefusedReadIsNotRecorded() {
	refused := ts.sendWith(testutils.GetRawHTTPClient(), http.MethodGet, "/variables", "")
	ts.Require().Equal(http.StatusUnauthorized, refused.StatusCode)
	traceID := refused.Header.Get(correlationIDHeader)

	ts.NotEmpty(ts.accessLogLine(traceID), "the read was not served")
	ts.Never(func() bool {
		lines, err := ts.reader.Read()
		return err != nil || len(lines) > 0
	}, quietPeriod, 100*time.Millisecond, "a refused read wrote an audit line")
}

// The level and format of diagnostic logging do not affect audit lines.
func (ts *AuditLogTestSuite) TestAuditLinesIgnoreTheLogLevelAndFormat() {
	ts.restartWith(ts.originalAudit, map[string]interface{}{
		"level": "error",
		"output": map[string]interface{}{
			"console": map[string]interface{}{"enabled": true},
			"file":    map[string]interface{}{"format": "json"},
		},
	})
	name := ts.prefix + "QUIET_LOG"

	ts.Require().Equal(http.StatusCreated, ts.send(http.MethodPut, "/variables/"+name, `{"value":"x"}`).StatusCode)
	ts.Require().Equal(http.StatusNoContent, ts.send(http.MethodDelete, "/variables/"+name, "").StatusCode)

	line, err := ts.reader.Await(func(line testutils.AuditLine) bool {
		return line.Target.ID == name && line.Action == "delete"
	})
	ts.Require().NoError(err, "no audit line was written at log level error with JSON output")
	ts.True(strings.HasPrefix(line.Raw, `{"log_type":"AUDIT",`))
}

// With audit off a management call still succeeds and writes no audit line.
func (ts *AuditLogTestSuite) TestAuditOffWritesNoLine() {
	ts.restartWith(map[string]interface{}{"enabled": false}, ts.originalLog)
	name := ts.prefix + "OFF"

	ts.Require().Equal(http.StatusCreated, ts.send(http.MethodPut, "/variables/"+name, `{"value":"x"}`).StatusCode)
	deleted := ts.send(http.MethodDelete, "/variables/"+name, "")
	ts.Require().Equal(http.StatusNoContent, deleted.StatusCode)

	ts.NotEmpty(ts.accessLogLine(deleted.Header.Get(correlationIDHeader)), "the delete was not served")
	ts.Never(func() bool {
		lines, err := ts.reader.Read()
		return err != nil || len(lines) > 0
	}, quietPeriod, 100*time.Millisecond, "an audit line was written with audit off")
}

// An invalid audit or marker configuration stops the server from starting, whichever component
// refuses it.
func (ts *AuditLogTestSuite) TestAnInvalidAuditConfigurationStopsTheServerStarting() {
	for _, tc := range []struct {
		name  string
		audit interface{}
		log   interface{}
		cause string
	}{
		{"a negative queue size", map[string]interface{}{"queue_size": -1}, ts.originalLog, "queue size is negative"},
		{"an instance id that is too long", map[string]interface{}{"instance_id": strings.Repeat("i", 256)},
			ts.originalLog, "audit.instance_id"},
		{"an unsupported delivery guarantee", map[string]interface{}{"delivery": "at_least_once"}, ts.originalLog,
			"unsupported delivery guarantee"},
		{"a marker key with a space", ts.originalAudit,
			map[string]interface{}{"type": map[string]interface{}{"key": "log type"}}, "log.type.key"},
	} {
		ts.Run(tc.name, func() {
			ts.configModified = true
			ts.Require().NoError(testutils.PatchDeploymentConfig(map[string]interface{}{
				auditConfigKey: tc.audit,
				logConfigKey:   tc.log,
			}))
			offset := ts.serverLogSize()

			ts.Require().NoError(testutils.StartServerExpectingExit(exitTimeout),
				"the server started with %s", tc.name)
			ts.Contains(ts.serverLogSince(offset), tc.cause)
		})
	}
}

// restartWith restarts the server with the audit and log sections replaced, and reads only what it
// writes from then on.
func (ts *AuditLogTestSuite) restartWith(audit, log interface{}) {
	ts.configModified = true
	ts.Require().NoError(testutils.PatchDeploymentConfig(map[string]interface{}{
		auditConfigKey: audit,
		logConfigKey:   log,
	}), "failed to patch the audit and log config")
	ts.Require().NoError(testutils.RestartServer(), "failed to restart the server")
	ts.Require().NoError(testutils.ObtainAdminAccessToken(), "failed to re-obtain the admin token")
	ts.Require().NoError(ts.reader.Reset())
}

// send makes a management call as the admin.
func (ts *AuditLogTestSuite) send(method, path, body string) *http.Response {
	ts.T().Helper()
	return ts.sendWith(testutils.GetHTTPClient(), method, path, body)
}

// sendWith makes a management call with client.
func (ts *AuditLogTestSuite) sendWith(client *http.Client, method, path, body string) *http.Response {
	ts.T().Helper()
	resp, _ := ts.exchange(client, method, path, body)
	return resp
}

// exchange makes a management call with client and returns the response and its body.
func (ts *AuditLogTestSuite) exchange(client *http.Client, method, path, body string) (*http.Response, []byte) {
	ts.T().Helper()
	var reader io.Reader
	if body != "" {
		reader = bytes.NewReader([]byte(body))
	}
	req, err := http.NewRequest(method, testutils.TestServerURL+path, reader)
	ts.Require().NoError(err)
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := client.Do(req)
	ts.Require().NoError(err)
	read, err := io.ReadAll(resp.Body)
	ts.Require().NoError(err)
	ts.Require().NoError(resp.Body.Close())
	return resp, read
}

// tokenRequestWithAnUnknownClient makes a token request a client authentication refuses, a protocol
// call the management middleware does not record.
func (ts *AuditLogTestSuite) tokenRequestWithAnUnknownClient() int {
	form := url.Values{"grant_type": {"client_credentials"}}
	req, err := http.NewRequest(http.MethodPost, testutils.TestServerURL+"/oauth2/token",
		strings.NewReader(form.Encode()))
	ts.Require().NoError(err)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(ts.prefix+"unknown_client", "secret")
	resp, err := testutils.GetRawHTTPClient().Do(req)
	ts.Require().NoError(err)
	ts.Require().NoError(resp.Body.Close())
	return resp.StatusCode
}

// accessLogLine waits for the access log line carrying traceID and returns it.
func (ts *AuditLogTestSuite) accessLogLine(traceID string) string {
	ts.T().Helper()
	ts.Require().NotEmpty(traceID)
	var found string
	ts.Require().Eventually(func() bool {
		data, err := os.ReadFile(testutils.ServerLogPath())
		if err != nil {
			return false
		}
		for _, line := range strings.Split(string(data), "\n") {
			if strings.Contains(line, traceID) && !strings.HasPrefix(line, "{\"log_type\"") {
				found = line
				return true
			}
		}
		return false
	}, 30*time.Second, 250*time.Millisecond, "no access log line carries trace ID %s", traceID)
	return found
}

// serverLogSize is the length of the server log, where a later read starts.
func (ts *AuditLogTestSuite) serverLogSize() int64 {
	info, err := os.Stat(testutils.ServerLogPath())
	if os.IsNotExist(err) {
		return 0
	}
	ts.Require().NoError(err)
	return info.Size()
}

// serverLogSince returns what the server wrote after offset.
func (ts *AuditLogTestSuite) serverLogSince(offset int64) string {
	data, err := os.ReadFile(testutils.ServerLogPath())
	ts.Require().NoError(err)
	return string(data[min(offset, int64(len(data))):])
}

// onlyLineOf waits for the audit line of the call that got response and returns it, after checking the
// call wrote no other line.
func (ts *AuditLogTestSuite) onlyLineOf(response *http.Response) testutils.AuditLine {
	ts.T().Helper()
	return ts.linesOf(response, 1)[0]
}

// linesOf waits for the want audit lines of the call that got response and returns them in the order
// they were written, after checking the call wrote no more.
func (ts *AuditLogTestSuite) linesOf(response *http.Response, want int) []testutils.AuditLine {
	ts.T().Helper()
	traceID := response.Header.Get(correlationIDHeader)
	ts.Require().NotEmpty(traceID)
	ofCall := func() ([]testutils.AuditLine, error) {
		lines, err := ts.reader.Read()
		var matched []testutils.AuditLine
		for _, line := range lines {
			if line.TraceID == traceID {
				matched = append(matched, line)
			}
		}
		return matched, err
	}
	ts.Require().Eventually(func() bool {
		lines, err := ofCall()
		return err == nil && len(lines) >= want
	}, 30*time.Second, 250*time.Millisecond, "the call wrote fewer than %d audit lines", want)
	ts.Never(func() bool {
		lines, err := ofCall()
		return err != nil || len(lines) > want
	}, quietPeriod, 100*time.Millisecond, "the call wrote more than %d audit lines", want)
	lines, err := ofCall()
	ts.Require().NoError(err)
	ts.Require().Len(lines, want)
	return lines
}

// unusedUserID returns a user ID no user of this or an earlier run has.
func unusedUserID() string {
	return fmt.Sprintf("01900000-0000-7000-8000-%012x", time.Now().UnixNano()&0xffffffffffff)
}

// adminUserID returns the ID of the user the admin token was issued to.
func (ts *AuditLogTestSuite) adminUserID() string {
	ts.T().Helper()
	resp, body := ts.exchange(testutils.GetHTTPClient(), http.MethodGet, "/users/me", "")
	ts.Require().Equal(http.StatusOK, resp.StatusCode, string(body))
	var admin testutils.User
	ts.Require().NoError(json.Unmarshal(body, &admin))
	ts.Require().NotEmpty(admin.ID)
	return admin.ID
}

// awaitDenied waits for the denied line of the refused request with traceID.
func (ts *AuditLogTestSuite) awaitDenied(traceID string) testutils.AuditLine {
	ts.T().Helper()
	ts.Require().NotEmpty(traceID)
	line, err := ts.reader.Await(func(line testutils.AuditLine) bool {
		return line.Outcome["result"] == deniedResult && line.TraceID == traceID
	})
	ts.Require().NoError(err, "the refused call wrote no denied line")
	return line
}

// createUserType creates an organization unit and a user type in it with a username and a password,
// both removed when the test ends, and returns the unit's ID and the type's handle. name keeps the
// handles of two calls in one run apart.
func (ts *AuditLogTestSuite) createUserType(name string) (string, string) {
	ts.T().Helper()
	handle := strings.ReplaceAll(strings.ToLower(ts.prefix), "_", "-") + name
	ouID, err := testutils.CreateOrganizationUnit(testutils.OrganizationUnit{
		Handle: handle + "-ou",
		Name:   "Audit Log Test OU",
	})
	ts.Require().NoError(err)
	ts.T().Cleanup(func() { _ = testutils.DeleteOrganizationUnit(ouID) })

	userType := testutils.UserType{
		Handle:      handle + "-person",
		DisplayName: "Audit Log Test Person",
		OUID:        ouID,
		Schema: map[string]interface{}{
			"username": map[string]interface{}{"type": "string"},
			"password": map[string]interface{}{"type": "string", "credential": true},
		},
	}
	userTypeID, err := testutils.CreateUserType(userType)
	ts.Require().NoError(err)
	ts.T().Cleanup(func() { _ = testutils.DeleteUserType(userTypeID) })
	return ouID, userType.Handle
}

// createUserWithoutPermissions creates a user who holds no management permission, removed when the
// test ends, and returns its ID and a client that calls with its token.
func (ts *AuditLogTestSuite) createUserWithoutPermissions() (string, *http.Client) {
	ts.T().Helper()
	ouID, userType := ts.createUserType("refused")

	username := strings.ToLower(ts.prefix) + "user"
	password := "AuditLogTest123!"
	attributes, err := json.Marshal(map[string]interface{}{"username": username, "password": password})
	ts.Require().NoError(err)
	userID, err := testutils.CreateUser(testutils.User{OUID: ouID, Type: userType, Attributes: attributes})
	ts.Require().NoError(err)
	ts.T().Cleanup(func() { _ = testutils.DeleteUser(userID) })

	client, err := testutils.GetHTTPClientForUser(username, password)
	ts.Require().NoError(err)
	return userID, client
}
