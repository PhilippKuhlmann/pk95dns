package dnsserver

import (
	"net/netip"
	"sync"
	"time"
)

const (
	// rateCleanEvery is how often idle buckets are removed (checked on use, no goroutine).
	rateCleanEvery = 30 * time.Second
	// rateIdle: a bucket unused for this long is full again and can be dropped.
	rateIdle = 10 * time.Second
)

// rateLimiter is a token bucket per client IP (burst = rate). Safe for concurrent use.
type rateLimiter struct {
	mu        sync.Mutex
	rate      int
	buckets   map[netip.Addr]*tokenBucket
	lastClean time.Time
}

type tokenBucket struct {
	tokens  float64
	last    time.Time
	lastLog time.Time // last time a dropped query of this client was logged
}

func newRateLimiter() *rateLimiter {
	return &rateLimiter{buckets: map[netip.Addr]*tokenBucket{}}
}

// setRate changes the limit; the per-client state is cleared when it changes.
func (l *rateLimiter) setRate(rate int) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if rate == l.rate {
		return
	}
	l.rate = rate
	l.buckets = map[netip.Addr]*tokenBucket{}
}

// allow takes a token for a. ok false means the query is dropped; logIt reports whether
// that drop should be logged (at most once per second per client).
func (l *rateLimiter) allow(a netip.Addr, now time.Time) (ok, logIt bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.rate <= 0 {
		return true, false
	}
	if now.Sub(l.lastClean) >= rateCleanEvery {
		l.clean(now)
	}
	burst := float64(l.rate)
	b := l.buckets[a]
	if b == nil {
		b = &tokenBucket{tokens: burst, last: now}
		l.buckets[a] = b
	} else if el := now.Sub(b.last); el > 0 {
		b.tokens = min(burst, b.tokens+el.Seconds()*burst)
		b.last = now
	}
	if b.tokens >= 1 {
		b.tokens--
		return true, false
	}
	if b.lastLog.IsZero() || now.Sub(b.lastLog) >= time.Second {
		b.lastLog = now
		return false, true
	}
	return false, false
}

// clean drops idle buckets. l.mu must be held.
func (l *rateLimiter) clean(now time.Time) {
	l.lastClean = now
	for a, b := range l.buckets {
		if now.Sub(b.last) >= rateIdle {
			delete(l.buckets, a)
		}
	}
}

// size returns the number of tracked clients (tests).
func (l *rateLimiter) size() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.buckets)
}
