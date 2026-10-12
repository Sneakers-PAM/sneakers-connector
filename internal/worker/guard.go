// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package worker

import (
	"fmt"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Sneakers-PAM/sneakers-connector/internal/adapter"
)

// now is the worker's clock; tests replace it.
var now = time.Now

// A target that can't be reached is not contacted again until backoffBase,
// then twice that, and so on up to backoffMax, however often the vault hands
// out its heartbeat. A good result clears it.
const (
	backoffBase = 5 * time.Minute
	backoffMax  = time.Hour
)

// targetGuard remembers, for the life of one worker run, the targets the
// heartbeat must not contact yet: an unreachable one until its backoff ends,
// and one that presented a host key matching none of its pins until it is
// re-pinned. A target is its protocol, address and pins, so re-pinning it
// (or moving it) makes a new target that is tried at once. A restarted
// connector starts with no memory and tries each target once more.
type targetGuard struct {
	mu      sync.Mutex
	targets map[string]*guardEntry
}

type guardEntry struct {
	result    adapter.Result
	detail    string
	failures  int
	notBefore time.Time
	stopped   bool
}

func newTargetGuard() *targetGuard {
	return &targetGuard{targets: map[string]*guardEntry{}}
}

func guardKey(protocol string, c adapter.Conn) string {
	pins := slices.Clone(c.HostKeys)
	slices.Sort(pins)
	return protocol + "|" + c.Host + "|" + strconv.Itoa(c.Port) + "|" + strings.Join(pins, "|")
}

// hold reports whether the target must not be contacted now, with the result
// and detail to report instead.
func (g *targetGuard) hold(key string) (adapter.Result, string, bool) {
	g.mu.Lock()
	defer g.mu.Unlock()
	e, ok := g.targets[key]
	switch {
	case !ok:
		return 0, "", false
	case e.stopped:
		return e.result, e.detail + "; heartbeat stopped for this target until its host key is re-pinned; no connection was made", true
	case now().Before(e.notBefore):
		return e.result, fmt.Sprintf("%s; backing off after %d failed attempts, next attempt after %s; no connection was made",
			e.detail, e.failures, e.notBefore.UTC().Format(time.RFC3339)), true
	default:
		return 0, "", false
	}
}

// record notes the outcome of an attempt that contacted the target and
// returns the backoff it starts, if any.
func (g *targetGuard) record(key string, result adapter.Result, detail string) (backoff time.Duration, stopped bool) {
	g.mu.Lock()
	defer g.mu.Unlock()
	switch result {
	case adapter.HostKeyMismatch:
		g.targets[key] = &guardEntry{result: result, detail: detail, stopped: true}
		return 0, true
	case adapter.Unreachable:
		e, ok := g.targets[key]
		if !ok {
			e = &guardEntry{}
			g.targets[key] = e
		}
		e.result, e.detail = result, detail
		e.failures++
		backoff = backoffMax
		if e.failures <= 30 {
			backoff = min(backoffBase<<(e.failures-1), backoffMax)
		}
		e.notBefore = now().Add(backoff)
		return backoff, false
	default:
		delete(g.targets, key)
		return 0, false
	}
}
