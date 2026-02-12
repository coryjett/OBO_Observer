package main

import (
	"slices"
	"sync"
)

type EventStore struct {
	mu       sync.RWMutex
	events   []Event
	capacity int
}

func NewEventStore(capacity int) *EventStore {
	if capacity < 1 {
		capacity = 500
	}
	return &EventStore{
		events:   make([]Event, 0, capacity),
		capacity: capacity,
	}
}

func (s *EventStore) Add(event Event) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.events = append(s.events, event)
	if len(s.events) > s.capacity {
		s.events = s.events[len(s.events)-s.capacity:]
	}
}

func (s *EventStore) List(limit int) []Event {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if limit < 1 || limit > len(s.events) {
		limit = len(s.events)
	}

	start := len(s.events) - limit
	result := make([]Event, limit)
	copy(result, s.events[start:])
	slices.Reverse(result)
	return result
}

func (s *EventStore) Clear() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.events = make([]Event, 0, s.capacity)
}

// LogBuffer holds the last N raw log lines for the UI.
type LogBuffer struct {
	mu       sync.RWMutex
	lines    []string
	capacity int
}

func NewLogBuffer(capacity int) *LogBuffer {
	if capacity < 1 {
		capacity = 500
	}
	return &LogBuffer{
		lines:    make([]string, 0, capacity),
		capacity: capacity,
	}
}

func (b *LogBuffer) Add(line string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.lines = append(b.lines, line)
	if len(b.lines) > b.capacity {
		b.lines = b.lines[len(b.lines)-b.capacity:]
	}
}

func (b *LogBuffer) List(limit int) []string {
	b.mu.RLock()
	defer b.mu.RUnlock()
	n := len(b.lines)
	if limit <= 0 || limit > n {
		limit = n
	}
	out := make([]string, limit)
	copy(out, b.lines[n-limit:])
	return out
}

// LogBroadcaster broadcasts new log lines to SSE clients. Safe for concurrent use.
type LogBroadcaster struct {
	mu   sync.Mutex
	subs map[chan string]struct{}
}

func NewLogBroadcaster() *LogBroadcaster {
	return &LogBroadcaster{subs: make(map[chan string]struct{})}
}

func (lb *LogBroadcaster) Subscribe() chan string {
	ch := make(chan string, 128)
	lb.mu.Lock()
	lb.subs[ch] = struct{}{}
	lb.mu.Unlock()
	return ch
}

func (lb *LogBroadcaster) Unsubscribe(ch chan string) {
	lb.mu.Lock()
	delete(lb.subs, ch)
	lb.mu.Unlock()
	close(ch)
}

func (lb *LogBroadcaster) Broadcast(line string) {
	lb.mu.Lock()
	for ch := range lb.subs {
		select {
		case ch <- line:
		default:
			// client slow, drop to avoid blocking
		}
	}
	lb.mu.Unlock()
}
