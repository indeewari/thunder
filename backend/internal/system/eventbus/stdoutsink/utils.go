// Copyright 2026 The ThunderID Authors
// SPDX-License-Identifier: Apache-2.0

package stdoutsink

import (
	"encoding/json"
	"maps"
	"reflect"
	"slices"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/thunder-id/thunderid/internal/system/config"
	"github.com/thunder-id/thunderid/internal/system/eventbus"
	"github.com/thunder-id/thunderid/internal/system/eventbus/audit"
)

// renderMarker validates the marker in cfg and renders it as a JSON member followed by a comma. The
// key must not name a line field, or a line would carry two members of that name.
func renderMarker(cfg config.LogTypeConfig) ([]byte, error) {
	if !typeKeyPattern.MatchString(cfg.Key) || slices.Contains(lineFieldNames(), cfg.Key) {
		return nil, errInvalidTypeKey
	}
	if cfg.Audit == "" || strings.IndexFunc(cfg.Audit, unicode.IsSpace) >= 0 {
		return nil, errInvalidTypeValue
	}
	key, err := json.Marshal(cfg.Key)
	if err != nil {
		return nil, err
	}
	value, err := json.Marshal(cfg.Audit)
	if err != nil {
		return nil, err
	}
	marker := make([]byte, 0, len(key)+len(value)+2)
	marker = append(marker, key...)
	marker = append(marker, ':')
	marker = append(marker, value...)
	return append(marker, ','), nil
}

// lineFieldNames returns the JSON names of the line fields.
func lineFieldNames() []string {
	lineType := reflect.TypeFor[line]()
	names := make([]string, 0, lineType.NumField())
	for i := range lineType.NumField() {
		name, _, _ := strings.Cut(lineType.Field(i).Tag.Get("json"), ",")
		names = append(names, name)
	}
	return names
}

// newLine maps an audit event to its line.
func newLine(env eventbus.Envelope, payload audit.Payload) line {
	actor := payload.Actor()
	target := payload.Target()
	outcome := payload.Outcome()
	l := line{
		SchemaVersion: schemaVersion,
		ID:            env.ID,
		Time:          env.Time.UTC().Format(timeLayout),
		Event:         env.Name,
		TraceID:       env.TraceID,
		TraceParent:   env.TraceParent,
		DeploymentID:  env.DeploymentID,
		Source:        env.Source,
		InstanceID:    env.InstanceID,
		BootID:        env.BootID,
		Seq:           env.Seq,
		Actor:         refLine{Type: string(actor.Type), ID: actor.ID},
		OnBehalfOf:    optionalRef(payload.OnBehalfOf()),
		Subject:       optionalRef(payload.Subject()),
		Target:        refLine{Type: target.Type, ID: target.ID},
		Action:        string(payload.Action()),
		Outcome:       outcomeLine{Result: string(outcome.Result), Reason: outcome.Reason},
		Details:       payload.Details(),
	}
	if client := payload.Client(); client != (audit.Client{}) {
		l.Client = &clientLine{Address: client.Address, UserAgent: client.UserAgent}
	}
	return l
}

// optionalRef returns the line form of ref, nil for the zero Ref.
func optionalRef(ref audit.Ref) *refLine {
	if ref == (audit.Ref{}) {
		return nil
	}
	return &refLine{Type: ref.Type, ID: ref.ID}
}

// largestDetail returns the key of the largest detail, the first in key order on a tie.
func largestDetail(details map[string]string) string {
	largest, size := "", -1
	for _, key := range slices.Sorted(maps.Keys(details)) {
		if entry := len(key) + len(details[key]); entry > size {
			largest, size = key, entry
		}
	}
	return largest
}

// capFields cuts every free-form field of l to maxFieldBytes.
func capFields(l *line) {
	fields := []*string{
		&l.TraceID, &l.DeploymentID, &l.Source, &l.InstanceID, &l.Actor.Type, &l.Actor.ID,
		&l.Target.Type, &l.Target.ID, &l.Action, &l.Outcome.Reason,
	}
	for _, ref := range []*refLine{l.OnBehalfOf, l.Subject} {
		if ref != nil {
			fields = append(fields, &ref.Type, &ref.ID)
		}
	}
	if l.Client != nil {
		fields = append(fields, &l.Client.Address, &l.Client.UserAgent)
	}
	for _, field := range fields {
		*field = truncateBytes(*field, maxFieldBytes)
	}
}

// truncateBytes returns the longest prefix of value within limit bytes that ends on a rune boundary.
func truncateBytes(value string, limit int) string {
	if len(value) <= limit {
		return value
	}
	limit = max(limit, 0)
	for limit > 0 && !utf8.RuneStart(value[limit]) {
		limit--
	}
	return value[:limit]
}
