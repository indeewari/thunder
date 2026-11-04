// Copyright 2026 The ThunderID Authors
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"sync"
	"time"
)

// tokenBucket admits events at a steady rate with a burst. It is safe for concurrent use and never
// blocks beyond its own short lock.
type tokenBucket struct {
	mu     sync.Mutex
	rate   float64
	burst  float64
	tokens float64
	last   time.Time
	now    func() time.Time
}

// newTokenBucket creates a full bucket that admits rate events per second and at most burst at once.
func newTokenBucket(rate, burst int, now func() time.Time) *tokenBucket {
	return &tokenBucket{rate: float64(rate), burst: float64(burst), tokens: float64(burst), last: now(), now: now}
}

// allow reports whether one more event is admitted now, and takes its token if so.
func (b *tokenBucket) allow() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	now := b.now()
	if elapsed := now.Sub(b.last); elapsed > 0 {
		b.tokens = min(b.burst, b.tokens+elapsed.Seconds()*b.rate)
		b.last = now
	}
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}
