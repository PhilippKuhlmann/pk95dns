package app

import (
	"strings"
	"time"

	"pk95dns/internal/api"
	"pk95dns/internal/upstream"
)

// upstreamMonitor decides on upstream.down / upstream.up from the health of the main
// upstreams. Not safe for concurrent use (only the monitor loop calls it).
type upstreamMonitor struct {
	failingSince time.Time // start of the current all-failing period, zero = not failing
	down         bool      // upstream.down was sent
}

// check returns "down", "up" or "".
func (m *upstreamMonitor) check(health []upstream.Health, now time.Time) string {
	if allFailing(health, now) {
		if m.failingSince.IsZero() {
			m.failingSince = now
		}
		if !m.down && now.Sub(m.failingSince) >= upstreamDownAfter {
			m.down = true
			return "down"
		}
		return ""
	}
	m.failingSince = time.Time{}
	if m.down && anyOK(health) {
		m.down = false
		return "up"
	}
	return ""
}

// allFailing: every main upstream was asked, its last answer was bad and none answered
// well within the last 60 seconds.
func allFailing(health []upstream.Health, now time.Time) bool {
	if len(health) == 0 {
		return false
	}
	for _, h := range health {
		if h.OK || h.Queries == 0 {
			return false
		}
		if h.LastOK > 0 && now.Sub(time.UnixMilli(h.LastOK)) < upstreamDownAfter {
			return false
		}
	}
	return true
}

func anyOK(health []upstream.Health) bool {
	for _, h := range health {
		if h.OK {
			return true
		}
	}
	return false
}

// checkUpstreams runs every 10 seconds.
func (a *app) checkUpstreams() {
	health := a.upstreamHealth()
	switch a.monitor.check(health, a.now()) {
	case "down":
		addrs := make([]string, 0, len(health))
		var lastErr string
		for _, h := range health {
			addrs = append(addrs, h.Address)
			if h.LastError != "" {
				lastErr = h.LastError
			}
		}
		body := "Seit mehr als 60 Sekunden antwortet keiner der Upstreams (" + strings.Join(addrs, ", ") + ")."
		if lastErr != "" {
			body += " Letzter Fehler: " + lastErr
		}
		a.events.send(api.EventUpstreamDown, sevCritical, "Keine Upstream-DNS-Server erreichbar", body,
			map[string]any{"upstreams": addrs})
	case "up":
		var ok []string
		for _, h := range health {
			if h.OK {
				ok = append(ok, h.Address)
			}
		}
		a.events.send(api.EventUpstreamUp, sevInfo, "Upstream-DNS-Server wieder erreichbar",
			"Wieder erreichbar: "+strings.Join(ok, ", ")+".", map[string]any{"upstreams": ok})
	}
}
