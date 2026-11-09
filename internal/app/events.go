package app

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"
)

// Event delivery limits (app protocol section 4: buffer, give up after one hour).
const (
	eventMaxAge     = time.Hour
	eventMaxQueue   = 500
	eventRetryEvery = 30 * time.Second
	eventTimeout    = 10 * time.Second
)

// Severities.
const (
	sevInfo     = "info"
	sevWarning  = "warning"
	sevCritical = "critical"
)

// event is the JSON body of POST {CORE_URL}/api/v1/events.
type event struct {
	Type       string         `json:"type"`
	Severity   string         `json:"severity"`
	Title      string         `json:"title"`
	Body       string         `json:"body"`
	Data       map[string]any `json:"data"`
	OccurredAt string         `json:"occurred_at"`
}

type queuedEvent struct {
	ev     event
	queued time.Time
	seq    uint64
}

// eventSender delivers events to Core with an in-memory retry queue. A nil sender
// (standalone mode) drops everything.
type eventSender struct {
	url    string
	token  string
	client *http.Client
	now    func() time.Time
	retry  time.Duration

	mu    sync.Mutex
	queue []queuedEvent
	seq   uint64
	wake  chan struct{}

	sendMu sync.Mutex // one delivery round at a time
}

func newEventSender(coreURL, token string) *eventSender {
	return &eventSender{
		url:    strings.TrimRight(coreURL, "/") + "/api/v1/events",
		token:  token,
		client: &http.Client{Timeout: eventTimeout},
		now:    time.Now,
		retry:  eventRetryEvery,
		wake:   make(chan struct{}, 1),
	}
}

// send queues an event and wakes the sender.
func (s *eventSender) send(typ, severity, title, body string, data map[string]any) {
	if s == nil {
		return
	}
	if data == nil {
		data = map[string]any{}
	}
	now := s.now()
	ev := event{Type: typ, Severity: severity, Title: title, Body: body, Data: data,
		OccurredAt: now.UTC().Format(time.RFC3339)}
	s.mu.Lock()
	s.seq++
	s.queue = append(s.queue, queuedEvent{ev: ev, queued: now, seq: s.seq})
	if len(s.queue) > eventMaxQueue {
		dropped := len(s.queue) - eventMaxQueue
		slog.Warn("events: queue full, oldest events dropped", "dropped", dropped)
		s.queue = append([]queuedEvent(nil), s.queue[dropped:]...)
	}
	s.mu.Unlock()
	select {
	case s.wake <- struct{}{}:
	default:
	}
}

// pending returns the number of queued events.
func (s *eventSender) pending() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.queue)
}

// run delivers queued events right away and retries every 30 seconds until ctx is done;
// then it makes one last short attempt.
func (s *eventSender) run(ctx context.Context) {
	if s == nil {
		return
	}
	t := time.NewTicker(s.retry)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			final, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			s.deliver(final)
			cancel()
			return
		case <-s.wake:
			s.deliver(ctx)
		case <-t.C:
			s.deliver(ctx)
		}
	}
}

// deliver sends the queue in order and stops at the first failure (Core unreachable).
// Events older than one hour are dropped.
func (s *eventSender) deliver(ctx context.Context) {
	s.sendMu.Lock()
	defer s.sendMu.Unlock()
	for {
		s.mu.Lock()
		now := s.now()
		for len(s.queue) > 0 && now.Sub(s.queue[0].queued) > eventMaxAge {
			slog.Warn("events: dropped after one hour", "type", s.queue[0].ev.Type)
			s.queue = s.queue[1:]
		}
		if len(s.queue) == 0 {
			s.mu.Unlock()
			return
		}
		head := s.queue[0]
		s.mu.Unlock()

		if !s.post(ctx, head.ev) {
			return
		}
		s.mu.Lock()
		if len(s.queue) > 0 && s.queue[0].seq == head.seq {
			s.queue = s.queue[1:]
		}
		s.mu.Unlock()
	}
}

// post sends one event. true: done (2xx, or 422 – Core will never take it).
func (s *eventSender) post(ctx context.Context, ev event) bool {
	body, err := json.Marshal(ev)
	if err != nil {
		slog.Error("events: cannot encode", "type", ev.Type, "error", err)
		return true
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.url, bytes.NewReader(body))
	if err != nil {
		slog.Error("events: bad Core URL", "url", s.url, "error", err)
		return false
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", "Bearer "+s.token)
	resp, err := s.client.Do(req)
	if err != nil {
		slog.Warn("events: Core not reachable, will retry", "type", ev.Type, "error", err)
		return false
	}
	resp.Body.Close()
	switch {
	case resp.StatusCode >= 200 && resp.StatusCode < 300:
		return true
	case resp.StatusCode == http.StatusUnprocessableEntity:
		slog.Warn("events: Core rejected the event", "type", ev.Type)
		return true
	default:
		slog.Warn("events: Core answered with an error, will retry", "type", ev.Type, "status", resp.StatusCode)
		return false
	}
}
