package webvpn

import (
	"github.com/t3chn0m4g3/ciscoasa_honeypot/internal/eventlog"
	"strings"
	"time"
)

type transportLog struct {
	s    *Server
	addr string
}

func (w transportLog) Write(b []byte) (int, error) {
	ip, port := "", 0
	if _, rest, ok := strings.Cut(string(b), "from "); ok {
		addr, _, _ := strings.Cut(rest, ": ")
		ip, port = eventlog.Peer(addr)
	}
	_, dest := eventlog.Peer(w.addr)
	now := time.Now()
	w.s.summaries.Tick(now)
	w.s.mu.Lock()
	if now.Sub(w.s.transportStart) >= time.Second {
		w.s.transportStart = now
		w.s.transportCount = 0
	}
	if w.s.transportCount >= 20 {
		w.s.mu.Unlock()
		w.s.limited(ip, dest)
		return len(b), nil
	}
	w.s.transportCount++
	w.s.mu.Unlock()
	e := eventlog.Event{Type: "error", SrcIP: ip, SrcPort: port, DestPort: dest, Protocol: "tcp", Payload: "", ASA: eventlog.ASA{Profile: eventlog.Profile{Version: w.s.Profile.Version, Hostname: w.s.Profile.Hostname}, Error: eventlog.Bound(string(b), 1024)}}
	eventlog.Report(w.s.Log, e)
	return len(b), nil
}
