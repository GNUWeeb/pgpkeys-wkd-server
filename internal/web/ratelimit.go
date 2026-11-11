package web

import (
	"sync"
	"time"
)

// limiter allows each key at most limit events per sliding window. It is
// kept in memory: a restart resets it, which only gives a client one more
// window.
type limiter struct {
	mu     sync.Mutex
	limit  int
	window time.Duration
	events map[string][]time.Time
}

func newLimiter(limit int, window time.Duration) *limiter {
	return &limiter{limit: limit, window: window, events: make(map[string][]time.Time)}
}

// allow records an event for key at now and reports whether it is within
// the limit. Refused events are not recorded.
func (l *limiter) allow(key string, now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	cutoff := now.Add(-l.window)
	for k, ts := range l.events {
		if len(ts) == 0 || !ts[len(ts)-1].After(cutoff) {
			delete(l.events, k)
		}
	}
	ts := l.events[key]
	i := 0
	for i < len(ts) && !ts[i].After(cutoff) {
		i++
	}
	ts = ts[i:]
	if len(ts) >= l.limit {
		l.events[key] = ts
		return false
	}
	l.events[key] = append(ts, now)
	return true
}
