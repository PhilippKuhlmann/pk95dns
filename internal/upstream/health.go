package upstream

import (
	"context"
	"errors"
	"sync"
	"time"
)

// ewmaAlpha is the weight of a new sample in the moving averages.
const ewmaAlpha = 0.3

// healthState is the mutable health of one upstream address.
type healthState struct {
	mu        sync.Mutex
	queries   int64
	failures  int64
	avgMS     float64 // EWMA of good answers, 0 = no sample yet
	weightMS  float64 // EWMA including failure penalties, used by load_balance
	samples   int64   // number of weightMS samples
	ok        bool
	lastError string
	lastOK    int64
}

// registry keeps the health of all upstream addresses across Router rebuilds.
var registry = struct {
	mu sync.Mutex
	m  map[string]*healthState
}{m: map[string]*healthState{}}

func healthFor(addr string) *healthState {
	registry.mu.Lock()
	defer registry.mu.Unlock()
	h, ok := registry.m[addr]
	if !ok {
		h = &healthState{}
		registry.m[addr] = h
	}
	return h
}

// resetHealth clears the registry (tests).
func resetHealth() {
	registry.mu.Lock()
	registry.m = map[string]*healthState{}
	registry.mu.Unlock()
}

// record stores the outcome of one exchange. penalty is the RTT sample used for the
// load-balancing weight when the exchange failed. Exchanges cancelled by the caller
// (parallel mode losers, client gone) are not counted.
func (h *healthState) record(rtt time.Duration, err error, penalty time.Duration) {
	if err != nil && errors.Is(err, context.Canceled) {
		return
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	h.queries++
	if err != nil {
		h.failures++
		h.ok = false
		h.lastError = err.Error()
		h.addWeight(float64(max(rtt, penalty)) / float64(time.Millisecond))
		return
	}
	ms := float64(rtt) / float64(time.Millisecond)
	if h.avgMS == 0 {
		h.avgMS = ms
	} else {
		h.avgMS = h.avgMS*(1-ewmaAlpha) + ms*ewmaAlpha
	}
	h.addWeight(ms)
	h.ok = true
	h.lastError = ""
	h.lastOK = time.Now().UnixMilli()
}

func (h *healthState) addWeight(ms float64) {
	if ms < 0.01 {
		ms = 0.01
	}
	if h.samples == 0 {
		h.weightMS = ms
	} else {
		h.weightMS = h.weightMS*(1-ewmaAlpha) + ms*ewmaAlpha
	}
	h.samples++
}

// weight returns the load-balancing RTT estimate in ms, ok = false when unknown.
func (h *healthState) weight() (float64, bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.weightMS, h.samples > 0
}

func (h *healthState) snapshot(addr string) Health {
	h.mu.Lock()
	defer h.mu.Unlock()
	return Health{
		Address:   addr,
		OK:        h.ok,
		AvgMS:     float64(int64(h.avgMS*10+0.5)) / 10,
		Queries:   h.queries,
		Failures:  h.failures,
		LastError: h.lastError,
		LastOK:    h.lastOK,
	}
}
