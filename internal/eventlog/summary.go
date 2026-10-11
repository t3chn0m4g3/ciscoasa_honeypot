package eventlog

import (
	"sync"
	"time"
)

const SummaryLimit = 4096

type summaryKey struct {
	IP   string
	Port int
	Type string
}
type summaryCount struct {
	Event Event
	Start time.Time
}
type Summary struct {
	mu       sync.Mutex
	writer   *Writer
	counts   map[summaryKey]summaryCount
	overflow summaryCount
	last     time.Time
}

func NewSummary(w *Writer) *Summary {
	return &Summary{writer: w, counts: make(map[summaryKey]summaryCount)}
}
func (s *Summary) Add(e Event, now time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := summaryKey{e.SrcIP, e.DestPort, e.Type}
	v, found := s.counts[key]
	if !found && len(s.counts) >= SummaryLimit {
		v = s.overflow
		if v.Start.IsZero() {
			e.SrcIP = ""
			e.SrcPort = 0
			e.DestPort = 0
			v = summaryCount{Event: e, Start: now}
		}
		if v.Event.ASA.Count < 1<<30 {
			v.Event.ASA.Count++
		}
		s.overflow = v
		return
	}
	if !found {
		e.SrcPort = 0
		e.Payload = ""
		v = summaryCount{Event: e, Start: now}
	}
	if v.Event.ASA.Count < 1<<30 {
		v.Event.ASA.Count++
	}
	s.counts[key] = v
}
func (s *Summary) Tick(now time.Time) {
	s.mu.Lock()
	if now.Sub(s.last) < time.Second {
		s.mu.Unlock()
		return
	}
	s.last = now
	var ready []Event
	for k, v := range s.counts {
		if now.Sub(v.Start) >= time.Minute {
			ready = append(ready, v.Event)
			delete(s.counts, k)
		}
	}
	if !s.overflow.Start.IsZero() && now.Sub(s.overflow.Start) >= time.Minute {
		ready = append(ready, s.overflow.Event)
		s.overflow = summaryCount{}
	}
	s.mu.Unlock()
	for _, e := range ready {
		Report(s.writer, e)
	}
}
