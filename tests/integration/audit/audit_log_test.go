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
	_, _ = io.Copy(io.Discard, resp.Body)
	ts.Require().NoError(resp.Body.Close())
	return resp
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

// createUserWithoutPermissions creates a user who holds no management permission, removed when the
// test ends, and returns its ID and a client that calls with its token.
func (ts *AuditLogTestSuite) createUserWithoutPermissions() (string, *http.Client) {
	ts.T().Helper()
	suffix := strings.ToLower(ts.prefix)
	ouID, err := testutils.CreateOrganizationUnit(testutils.OrganizationUnit{
		Handle: strings.ReplaceAll(suffix, "_", "-") + "ou",
		Name:   "Audit Log Test OU",
	})
	ts.Require().NoError(err)
	ts.T().Cleanup(func() { _ = testutils.DeleteOrganizationUnit(ouID) })

	userType := testutils.UserType{
		Handle:      strings.ReplaceAll(suffix, "_", "-") + "person",
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

	username := suffix + "user"
	password := "AuditLogTest123!"
	attributes, err := json.Marshal(map[string]interface{}{"username": username, "password": password})
	ts.Require().NoError(err)
	userID, err := testutils.CreateUser(testutils.User{OUID: ouID, Type: userType.Handle, Attributes: attributes})
	ts.Require().NoError(err)
	ts.T().Cleanup(func() { _ = testutils.DeleteUser(userID) })

	client, err := testutils.GetHTTPClientForUser(username, password)
	ts.Require().NoError(err)
	return userID, client
}
