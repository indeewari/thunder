// Copyright 2026 The ThunderID Authors
// SPDX-License-Identifier: Apache-2.0

package defaultaudit

import (
	"bytes"
	"context"
	"io"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/suite"

	"github.com/thunder-id/thunderid/internal/system/config"
	"github.com/thunder-id/thunderid/internal/system/eventbus"
	"github.com/thunder-id/thunderid/internal/system/eventbus/audit"
)

const testInstanceID = "node-a"

type InitTestSuite struct {
	suite.Suite
}

func TestInitTestSuite(t *testing.T) {
	suite.Run(t, new(InitTestSuite))
}

// shippedConfig is the configuration default.json ships, with audit on or off.
func shippedConfig(enabled bool) Config {
	return Config{
		Source:          "server",
		ShutdownTimeout: 2 * time.Second,
		Audit: config.AuditConfig{
			Enabled:                &enabled,
			Delivery:               "best_effort",
			QueueSize:              1024,
			DeliveryTimeoutSeconds: 5,
			InstanceID:             testInstanceID,
		},
		LogType: config.LogTypeConfig{Key: "log_type", Audit: "AUDIT"},
	}
}

// managementEvent is a management call event published from outside a request.
func managementEvent(outcome audit.Outcome) *eventbus.Event {
	ctx := context.Background()
	return eventbus.NewEvent(ctx, audit.EventManagementRequest).
		With(audit.NewPayload(ctx, audit.Ref{Type: "variables", ID: "API_URL"}, audit.ActionDelete, outcome))
}

// captureStdout sends standard output to a pipe until the returned function is called, which returns
// what was written.
func (s *InitTestSuite) captureStdout() func() []byte {
	reader, writer, err := os.Pipe()
	s.Require().NoError(err)
	original := os.Stdout
	os.Stdout = writer
	s.T().Cleanup(func() { os.Stdout = original })
	return func() []byte {
		os.Stdout = original
		s.Require().NoError(writer.Close())
		written, err := io.ReadAll(reader)
		s.Require().NoError(err)
		return written
	}
}

// statsOf reads the subscriber counters the bus keeps, which only tests read.
func (s *InitTestSuite) statsOf(bus eventbus.EventBusInterface) []eventbus.SubscriberStats {
	counters, ok := bus.(interface {
		Stats() []eventbus.SubscriberStats
	})
	s.Require().True(ok, "the bus keeps no subscriber counters")
	return counters.Stats()
}

func (s *InitTestSuite) TestAuditOnWritesOneLineToStandardOutput() {
	read := s.captureStdout()
	bus, stopper, err := Initialize(shippedConfig(true))
	s.Require().NoError(err)

	s.Require().NoError(bus.Publish(context.Background(), managementEvent(audit.OutcomeSucceeded)))
	stopper.Stop()

	written := read()
	s.Equal(1, bytes.Count(written, []byte("\n")))
	s.True(bytes.HasPrefix(written, []byte(`{"log_type":"AUDIT","schema_version":1,`)))
	s.Contains(string(written), `"source":"server"`)
	s.Contains(string(written), `"instance_id":"`+testInstanceID+`"`)
	s.Equal([]eventbus.SubscriberStats{{ID: stdoutSubscriberID, Category: audit.CategoryAudit, Delivered: 1}},
		s.statsOf(bus))
}

// With audit off the bus still validates every event, then drops it.
func (s *InitTestSuite) TestAuditOffValidatesAndDrops() {
	read := s.captureStdout()
	bus, stopper, err := Initialize(shippedConfig(false))
	s.Require().NoError(err)

	s.NoError(bus.Publish(context.Background(), managementEvent(audit.OutcomeSucceeded)))
	s.Error(bus.Publish(context.Background(), managementEvent(audit.OutcomeDenied(""))))
	stopper.Stop()

	s.Empty(s.statsOf(bus))
	s.Empty(read())
}

func (s *InitTestSuite) TestAnEventOutsideTheCatalogIsRejected() {
	for _, enabled := range []bool{true, false} {
		bus, stopper, err := Initialize(shippedConfig(enabled))
		s.Require().NoError(err)
		ctx := context.Background()

		err = bus.Publish(ctx, eventbus.NewEvent(ctx, "user.renamed").
			With(audit.NewPayload(ctx, audit.Ref{Type: "users"}, audit.ActionUpdate, audit.OutcomeSucceeded)))

		s.Error(err)
		stopper.Stop()
	}
}

func (s *InitTestSuite) TestAnInvalidConfigurationFailsStartup() {
	unsupportedDelivery := shippedConfig(true)
	unsupportedDelivery.Audit.Delivery = "at_least_once"
	invalidKey := shippedConfig(false)
	invalidKey.LogType.Key = "log type"
	invalidValue := shippedConfig(true)
	invalidValue.LogType.Audit = ""
	noSource := shippedConfig(true)
	noSource.Source = ""
	negativeQueue := shippedConfig(true)
	negativeQueue.Audit.QueueSize = -1
	negativeTimeout := shippedConfig(false)
	negativeTimeout.Audit.DeliveryTimeoutSeconds = -1

	for name, cfg := range map[string]Config{
		"an unsupported delivery guarantee":      unsupportedDelivery,
		"an invalid marker key with audit off":   invalidKey,
		"an empty marker value":                  invalidValue,
		"a binary that does not name its source": noSource,
		"a negative queue size":                  negativeQueue,
		"a negative delivery timeout":            negativeTimeout,
	} {
		s.Run(name, func() {
			bus, stopper, err := Initialize(cfg)

			s.Error(err)
			s.Nil(bus)
			s.Nil(stopper)
		})
	}
}
