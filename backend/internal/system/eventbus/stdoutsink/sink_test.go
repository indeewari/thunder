// Copyright 2026 The ThunderID Authors
// SPDX-License-Identifier: Apache-2.0

package stdoutsink

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"io"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/stretchr/testify/suite"

	"github.com/thunder-id/thunderid/internal/system/config"
	"github.com/thunder-id/thunderid/internal/system/eventbus"
	"github.com/thunder-id/thunderid/internal/system/eventbus/audit"
)

const (
	testUserID = "01900000-0000-7000-8000-000000000030"
	testTarget = "variables"
)

var (
	defaultMarker = config.LogTypeConfig{Key: "log_type", Audit: "AUDIT"}

	// lineTimePattern is the time format of a line: UTC with exactly six fractional digits.
	lineTimePattern = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}Z$`)
)

// knownLine is how a consumer of schema version 1 reads a line.
type knownLine struct {
	LogType       string            `json:"log_type"`
	SchemaVersion int               `json:"schema_version"`
	ID            string            `json:"id"`
	Time          string            `json:"time"`
	Event         string            `json:"event"`
	TraceID       string            `json:"trace_id"`
	TraceParent   string            `json:"traceparent"`
	DeploymentID  string            `json:"deployment_id"`
	Source        string            `json:"source"`
	InstanceID    string            `json:"instance_id"`
	BootID        string            `json:"boot_id"`
	Seq           uint64            `json:"seq"`
	Actor         map[string]string `json:"actor"`
	OnBehalfOf    map[string]string `json:"on_behalf_of"`
	Subject       map[string]string `json:"subject"`
	Target        map[string]string `json:"target"`
	Action        string            `json:"action"`
	Outcome       map[string]string `json:"outcome"`
	Client        map[string]string `json:"client"`
	Details       map[string]string `json:"details"`
}

type SinkTestSuite struct {
	suite.Suite
}

func TestSinkTestSuite(t *testing.T) {
	suite.Run(t, new(SinkTestSuite))
}

// envelope is what the bus fills in for one event, published in a zone other than UTC.
func envelope() eventbus.Envelope {
	return eventbus.Envelope{
		ID:           "01934f6e-7a2b-7c3d-8e4f-5a6b7c8d9e0f",
		Name:         audit.EventManagementRequest,
		Time:         time.Date(2026, 11, 2, 23, 4, 20, 145326000, time.FixedZone("IST", 19800)),
		TraceID:      "56672f4d-0d6e-4a4b-9f0e-6c1d2e3f4a5b",
		TraceParent:  "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01",
		DeploymentID: "default-deployment",
		Source:       "server",
		InstanceID:   "host-1",
		BootID:       "81997076-1a2b-4c3d-8e4f-5a6b7c8d9e0f",
		Seq:          7,
	}
}

// payload is an audit payload as a management call builds it, with a client.
func payload() audit.Payload {
	return audit.NewPayload(context.Background(), audit.Ref{Type: testTarget, ID: "API_URL"}, audit.ActionUpdate,
		audit.OutcomeSucceeded).WithClient(audit.Client{Address: "127.0.0.1", UserAgent: "Go-http-client/1.1"})
}

// write handles one event with a sink that writes to a buffer and returns what it wrote.
func (s *SinkTestSuite) write(marker config.LogTypeConfig, env eventbus.Envelope, p audit.Payload) []byte {
	var out bytes.Buffer
	sink, err := newStdoutSink(&out, marker)
	s.Require().NoError(err)
	s.Require().NoError(sink.Handle(context.Background(), env, p))
	return out.Bytes()
}

// decode parses one written line, asserting it is a single newline-terminated JSON object.
func (s *SinkTestSuite) decode(written []byte) knownLine {
	s.Require().True(bytes.HasSuffix(written, []byte("\n")), "a line ends with a newline")
	s.Require().Equal(1, bytes.Count(written, []byte("\n")), "an event is exactly one line")
	s.Require().True(json.Valid(written), "a line is valid JSON: %s", written)
	var decoded knownLine
	s.Require().NoError(json.Unmarshal(written, &decoded))
	return decoded
}

// keys returns the top-level keys of a JSON object in the order they were written.
func (s *SinkTestSuite) keys(written []byte) []string {
	decoder := json.NewDecoder(bytes.NewReader(written))
	_, err := decoder.Token()
	s.Require().NoError(err)
	var keys []string
	for decoder.More() {
		token, err := decoder.Token()
		s.Require().NoError(err)
		keys = append(keys, token.(string))
		var skip json.RawMessage
		s.Require().NoError(decoder.Decode(&skip))
	}
	return keys
}

func (s *SinkTestSuite) TestALineCarriesTheMarkerFirstAndTheWholeEvent() {
	written := s.write(defaultMarker, envelope(),
		payload().WithSubject(audit.Ref{Type: "user", ID: testUserID}).
			WithOnBehalfOf(audit.Ref{Type: "user", ID: testUserID}).
			WithDetails(map[string]string{"grant_type": "client_credentials"}))

	s.True(bytes.HasPrefix(written, []byte(`{"log_type":"AUDIT",`)))
	s.Equal([]string{
		"log_type", "schema_version", "id", "time", "event", "trace_id", "traceparent", "deployment_id",
		"source", "instance_id", "boot_id", "seq", "actor", "on_behalf_of", "subject", "target", "action",
		"outcome", "client", "details",
	}, s.keys(written))

	decoded := s.decode(written)
	env := envelope()
	s.Equal(1, decoded.SchemaVersion)
	s.Equal(env.ID, decoded.ID)
	s.Equal("2026-11-02T17:34:20.145326Z", decoded.Time)
	s.Equal(env.Name, decoded.Event)
	s.Equal(env.TraceID, decoded.TraceID)
	s.Equal(env.TraceParent, decoded.TraceParent)
	s.Equal(env.DeploymentID, decoded.DeploymentID)
	s.Equal(env.Source, decoded.Source)
	s.Equal(env.InstanceID, decoded.InstanceID)
	s.Equal(env.BootID, decoded.BootID)
	s.Equal(env.Seq, decoded.Seq)
	s.Equal(map[string]string{"type": "anonymous"}, decoded.Actor)
	s.Equal(map[string]string{"type": "user", "id": testUserID}, decoded.OnBehalfOf)
	s.Equal(map[string]string{"type": "user", "id": testUserID}, decoded.Subject)
	s.Equal(map[string]string{"type": testTarget, "id": "API_URL"}, decoded.Target)
	s.Equal("update", decoded.Action)
	s.Equal(map[string]string{"result": "succeeded"}, decoded.Outcome)
	s.Equal(map[string]string{"address": "127.0.0.1", "user_agent": "Go-http-client/1.1"}, decoded.Client)
	s.Equal(map[string]string{"grant_type": "client_credentials"}, decoded.Details)
}

func (s *SinkTestSuite) TestTheTimeIsUTCWithSixFractionalDigits() {
	env := envelope()
	env.Time = time.Date(2026, 11, 2, 17, 34, 20, 0, time.UTC)

	decoded := s.decode(s.write(defaultMarker, env, payload()))

	s.Regexp(lineTimePattern, decoded.Time)
	s.Equal("2026-11-02T17:34:20.000000Z", decoded.Time)
}

func (s *SinkTestSuite) TestOptionalFieldsAreLeftOut() {
	env := envelope()
	env.TraceID = ""
	env.TraceParent = ""
	p := audit.NewPayload(context.Background(), audit.Ref{Type: testTarget}, audit.ActionCreate,
		audit.OutcomeFailed("http_500"))

	written := s.write(defaultMarker, env, p)

	s.Equal([]string{
		"log_type", "schema_version", "id", "time", "event", "trace_id", "deployment_id", "source",
		"instance_id", "boot_id", "seq", "actor", "target", "action", "outcome",
	}, s.keys(written))
	decoded := s.decode(written)
	s.Equal(map[string]string{"type": testTarget}, decoded.Target)
	s.Equal(map[string]string{"result": "failed", "reason": "http_500"}, decoded.Outcome)
}

// details is a nested object, so a key in it cannot take the place of the top-level marker.
func (s *SinkTestSuite) TestDetailsCannotReplaceTheMarker() {
	written := s.write(defaultMarker, envelope(), payload().WithDetails(map[string]string{"log_type": "DIAGNOSTIC"}))

	s.True(bytes.HasPrefix(written, []byte(`{"log_type":"AUDIT",`)))
	decoded := s.decode(written)
	s.Equal("AUDIT", decoded.LogType)
	s.Equal(map[string]string{"log_type": "DIAGNOSTIC"}, decoded.Details)
}

func (s *SinkTestSuite) TestACustomMarkerIsUsed() {
	written := s.write(config.LogTypeConfig{Key: "record_kind", Audit: "SECURITY_AUDIT"}, envelope(), payload())

	s.True(bytes.HasPrefix(written, []byte(`{"record_kind":"SECURITY_AUDIT","schema_version":1,`)))
	s.True(json.Valid(written))
}

func (s *SinkTestSuite) TestAnInvalidMarkerIsRefused() {
	for _, tc := range []struct {
		name   string
		marker config.LogTypeConfig
		err    error
	}{
		{"an empty key", config.LogTypeConfig{Audit: "AUDIT"}, errInvalidTypeKey},
		{"a key with a space", config.LogTypeConfig{Key: "log type", Audit: "AUDIT"}, errInvalidTypeKey},
		{"a key with a hyphen", config.LogTypeConfig{Key: "log-type", Audit: "AUDIT"}, errInvalidTypeKey},
		{"a key that is a line field", config.LogTypeConfig{Key: "event", Audit: "AUDIT"}, errInvalidTypeKey},
		{"a key that is the actor field", config.LogTypeConfig{Key: "actor", Audit: "AUDIT"}, errInvalidTypeKey},
		{"an empty value", config.LogTypeConfig{Key: "log_type"}, errInvalidTypeValue},
		{"a value with a space", config.LogTypeConfig{Key: "log_type", Audit: "AU DIT"}, errInvalidTypeValue},
		{"a value with a newline", config.LogTypeConfig{Key: "log_type", Audit: "AUDIT\n"}, errInvalidTypeValue},
	} {
		s.Run(tc.name, func() {
			sink, err := Initialize(tc.marker)

			s.ErrorIs(err, tc.err)
			s.Nil(sink)
		})
	}
}

// A consumer that knows schema version 1 reads the same values from a line that gained a field.
func (s *SinkTestSuite) TestAnAddedFieldLeavesTheKnownFieldsUnchanged() {
	written := s.write(defaultMarker, envelope(), payload())
	extended := append([]byte(`{"added_later":{"nested":true},`), written[1:]...)

	s.Equal(s.decode(written), s.decode(extended))
}

func (s *SinkTestSuite) TestAnOversizedLineDropsTheLargestDetailsFirst() {
	p := payload().WithDetails(map[string]string{
		"largest": strings.Repeat("l", maxLineBytes),
		"larger":  strings.Repeat("m", maxLineBytes-maxFieldBytes),
		"fits":    strings.Repeat("f", maxLineBytes/4),
		"small":   "kept",
	})

	written := s.write(defaultMarker, envelope(), p)

	s.LessOrEqual(len(written), maxLineBytes)
	decoded := s.decode(written)
	s.Equal(map[string]string{"fits": strings.Repeat("f", maxLineBytes/4), "small": "kept"}, decoded.Details,
		"only as many details as needed are dropped, largest first")
	s.Equal("Go-http-client/1.1", decoded.Client["user_agent"], "the user agent is kept while details suffice")
}

func (s *SinkTestSuite) TestThenTheUserAgent() {
	p := payload().
		WithDetails(map[string]string{"large": strings.Repeat("d", maxLineBytes)}).
		WithClient(audit.Client{Address: "127.0.0.1", UserAgent: strings.Repeat("ü", maxLineBytes)})

	written := s.write(defaultMarker, envelope(), p)

	s.LessOrEqual(len(written), maxLineBytes)
	decoded := s.decode(written)
	s.Empty(decoded.Details)
	s.NotEmpty(decoded.Client["user_agent"], "the user agent is cut, not dropped, when cutting suffices")
	s.True(utf8.ValidString(decoded.Client["user_agent"]))
	s.True(strings.HasPrefix(strings.Repeat("ü", maxLineBytes), decoded.Client["user_agent"]))
	s.Equal(map[string]string{"type": testTarget, "id": "API_URL"}, decoded.Target)
}

// A caller controls the correlation ID and the path a target ID comes from, so either can be large.
func (s *SinkTestSuite) TestThenTheCallerControlledFields() {
	env := envelope()
	env.TraceID = strings.Repeat("t", 3*maxLineBytes)
	p := audit.NewPayload(context.Background(), audit.Ref{Type: testTarget, ID: strings.Repeat("\"", maxLineBytes)},
		audit.ActionUpdate, audit.OutcomeSucceeded)

	written := s.write(defaultMarker, env, p)

	s.LessOrEqual(len(written), maxLineBytes)
	s.True(bytes.HasPrefix(written, []byte(`{"log_type":"AUDIT",`)))
	decoded := s.decode(written)
	s.Equal(strings.Repeat("t", maxFieldBytes), decoded.TraceID)
	s.Equal(strings.Repeat("\"", 128), decoded.Target["id"])
	s.Equal(env.ID, decoded.ID)
}

// A long target ID reaches the line cut to 128 characters.
func (s *SinkTestSuite) TestALongTargetIDIsCutTo128Characters() {
	long := strings.Repeat("ü", 200)
	p := audit.NewPayload(context.Background(), audit.Ref{Type: testTarget, ID: long}, audit.ActionUpdate,
		audit.OutcomeSucceeded)

	decoded := s.decode(s.write(defaultMarker, envelope(), p))

	s.Equal(strings.Repeat("ü", 128), decoded.Target["id"])
}

func (s *SinkTestSuite) TestALineThatCannotFitIsNotWritten() {
	var out bytes.Buffer
	sink, err := newStdoutSink(&out, config.LogTypeConfig{Key: "log_type", Audit: strings.Repeat("A", maxLineBytes)})
	s.Require().NoError(err)

	s.ErrorIs(sink.Handle(context.Background(), envelope(), payload()), errLineTooLong)
	s.Zero(out.Len())
}

func (s *SinkTestSuite) TestAWriteFailureIsReturned() {
	closed, err := os.CreateTemp(s.T().TempDir(), "closed")
	s.Require().NoError(err)
	s.Require().NoError(closed.Close())
	sink, err := newStdoutSink(closed, defaultMarker)
	s.Require().NoError(err)

	s.Error(sink.Handle(context.Background(), envelope(), payload()))
}

func (s *SinkTestSuite) TestInitializeWritesToStandardOutput() {
	reader, writer, err := os.Pipe()
	s.Require().NoError(err)
	original := os.Stdout
	os.Stdout = writer
	defer func() { os.Stdout = original }()

	sink, err := Initialize(defaultMarker)
	os.Stdout = original
	s.Require().NoError(err)
	s.Require().NoError(sink.Handle(context.Background(), envelope(), payload()))
	s.Require().NoError(writer.Close())

	written, err := io.ReadAll(bufio.NewReader(reader))
	s.Require().NoError(err)
	s.Equal("AUDIT", s.decode(written).LogType)
}
