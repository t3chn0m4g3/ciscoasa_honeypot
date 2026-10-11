package ike

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"github.com/t3chn0m4g3/ciscoasa_honeypot/internal/eventlog"
	"github.com/t3chn0m4g3/ciscoasa_honeypot/internal/identity"
	"net"
	"strconv"
	"sync"
	"time"
)

type session struct {
	Peer           string
	Last           time.Time
	Next           time.Time
	Retries        int
	Response       []byte
	Request        []byte
	LatestRequest  []byte
	LatestResponse []byte
	Responder      [8]byte
	Group          uint16
	Keys           *keys
	Done           bool
}
type Server struct {
	Profile  *identity.Profile
	Log      *eventlog.Writer
	mu       sync.Mutex
	sessions map[string]*session
	rates    map[string]rate
}
type rate struct {
	Start time.Time
	Count int
}

func New(p *identity.Profile, l *eventlog.Writer) *Server {
	return &Server{Profile: p, Log: l, sessions: map[string]*session{}, rates: map[string]rate{}}
}
func (s *Server) vendors(version byte, natt bool) []Payload {
	typ := byte(13)
	if version>>4 == 2 {
		typ = 43
	}
	var minor, rev, interim int
	fmt.Sscanf(s.Profile.Version, "9.%d(%d)%d", &minor, &rev, &interim)
	values := []string{"12f5f28c457168a9702d9fe274cc0100", "09002689dfd6b712", "4048b7d56ebce88525e7de7f00d6c2d3c0000000", fmt.Sprintf("1f07f70eaa6514d3b0fa96542a%02x%02x%02x", minor, rev, interim), "afcad71368a1f1c96b8696fc77570100"}
	if natt {
		values = append(values, "4a131c81070358455c5728f20e95452f")
	}
	out := []Payload{}
	for _, v := range values {
		out = append(out, Payload{Type: typ, Data: vid(v)})
	}
	return out
}
func notify(p Packet, code uint16, extra []byte) []byte {
	if p.Version>>4 == 2 {
		p.Flags = 0x20
		b := []byte{0, 0, byte(code >> 8), byte(code)}
		b = append(b, extra...)
		return Encode(p, []Payload{{Type: 41, Data: b}})
	}
	p.Flags = 0
	p.Exchange = 5
	b := []byte{0, 0, 0, 1, 1, 0, byte(code >> 8), byte(code)}
	return Encode(p, []Payload{{Type: 11, Data: b}})
}
func (s *Server) Handle(raw []byte, peer string, port int) []byte {
	ip, src := eventlog.Peer(peer)
	e := eventlog.Event{Type: "ike.packet", SrcIP: ip, SrcPort: src, DestPort: port, Protocol: "udp", Payload: eventlog.Printable(raw), ASA: eventlog.ASA{Profile: eventlog.Profile{Version: s.Profile.Version, Hostname: s.Profile.Hostname}}}
	defer func() { eventlog.Report(s.Log, e) }()
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	for k, v := range s.sessions {
		if now.Sub(v.Last) > time.Minute {
			delete(s.sessions, k)
		}
	}
	for k, v := range s.rates {
		if now.Sub(v.Start) > time.Second {
			delete(s.rates, k)
		}
	}
	rate := s.rates[ip]
	if now.Sub(rate.Start) > time.Second {
		rate.Start = now
		rate.Count = 0
	}
	rate.Count++
	if len(s.rates) >= 4096 && rate.Count == 1 {
		return nil
	}
	s.rates[ip] = rate
	if rate.Count > 20 {
		return nil
	}
	p, err := Parse(raw)
	if err != nil {
		e.Type = "error"
		e.ASA.Error = err.Error()
		return nil
	}
	major := p.Version >> 4
	e.ASA.IKE = &eventlog.IKE{Version: strconv.Itoa(int(major)), Exchange: strconv.Itoa(int(p.Exchange)), Proposals: proposalSummary(p)}
	natt := false
	for _, x := range p.Payloads {
		if x.Type == 13 || x.Type == 43 {
			e.ASA.IKE.VendorIDs = append(e.ASA.IKE.VendorIDs, hex.EncodeToString(x.Data))
			if bytes.Equal(x.Data, vid("4a131c81070358455c5728f20e95452f")) {
				natt = true
			}
		}
		if x.Type == 132 || x.Type == 53 {
			e.Type = "ike.fragment"
			if len(x.Data) < 4 {
				e.CVE = []string{"CVE-2016-1287", "CVE-2018-0101"}
				e.ASA.Anomaly = "short IKE fragment heuristic"
			}
			return nil
		}
		if major == 1 && x.Type == 11 && len(x.Data) >= 8 && binary.BigEndian.Uint16(x.Data[6:8]) == 1 {
			e.CVE = append(e.CVE, "CVE-2016-6415")
			e.ASA.Anomaly = "BENIGNCERTAIN notify probe heuristic"
		}
	}
	key := peer + "/" + strconv.Itoa(port) + "/" + hex.EncodeToString(p.Initiator[:])
	st := s.sessions[key]
	if major == 2 && (p.Flags&0x20 != 0 || p.Flags&8 == 0) {
		return nil
	}
	if st != nil {
		if p.Responder != ([8]byte{}) && p.Responder != st.Responder {
			return nil
		}
		st.Last = now
		if bytes.Equal(raw, st.LatestRequest) {
			return append([]byte{}, st.LatestResponse...)
		}
		p.Responder = st.Responder
	}
	initial := major == 2 && p.Exchange == 34 && p.MessageID == 0 || major == 1 && (p.Exchange == 2 || p.Exchange == 4) && Find(p, 1) != nil
	if initial {
		if st != nil {
			if !bytes.Equal(raw, st.Request) {
				return nil
			}
			return append([]byte{}, st.Response...)
		}
		if len(s.sessions) >= 4096 {
			oldest := ""
			var when time.Time
			for k, v := range s.sessions {
				if oldest == "" || v.Last.Before(when) {
					oldest = k
					when = v.Last
				}
			}
			delete(s.sessions, oldest)
		}
		st = &session{Peer: peer, Last: now, Next: now.Add(8 * time.Second)}
		copy(st.Responder[:], random(8))
		p.Responder = st.Responder
		parts := []Payload{}
		if major == 2 {
			sa, suite, err := selectV2(Find(p, 33))
			if err != nil {
				return notify(p, 14, nil)
			}
			ke := Find(p, 34)
			ni := Find(p, 40)
			if len(ke) < 4 || len(ni) < 16 || len(ni) > 256 {
				return notify(p, 7, nil)
			}
			group := binary.BigEndian.Uint16(ke[:2])
			if group != suite.DH {
				return notify(p, 17, []byte{byte(suite.DH >> 8), byte(suite.DH)})
			}
			pub, secret, err := dh(group, ke[4:])
			if err != nil {
				return notify(p, 7, nil)
			}
			nr := random(32)
			keys := derive(suite, ni, nr, secret, p.Initiator, p.Responder)
			st.Keys = &keys
			st.Group = group
			p.Flags = 0x20
			parts = append(parts, Payload{Type: 33, Data: sa}, Payload{Type: 34, Data: append([]byte{byte(group >> 8), byte(group), 0, 0}, pub...)}, Payload{Type: 40, Data: nr})
		} else {
			sa, group, err := selectV1(Find(p, 1))
			if err != nil {
				return notify(p, 14, nil)
			}
			st.Group = group
			p.Flags = 0
			parts = append(parts, Payload{Type: 1, Data: sa})
			if p.Exchange == 4 {
				ke := Find(p, 4)
				nonce := Find(p, 10)
				id := Find(p, 5)
				if len(nonce) < 8 || len(nonce) > 256 || len(id) < 4 {
					return notify(p, 16, nil)
				}
				pub, _, err := dh(group, ke)
				if err != nil {
					return notify(p, 16, nil)
				}
				hashLen := 20
				for a := 24; a+4 <= len(sa); a += 4 {
					if binary.BigEndian.Uint16(sa[a:]) == 0x8002 && binary.BigEndian.Uint16(sa[a+2:]) == 4 {
						hashLen = 32
					}
				}
				parts = append(parts, Payload{Type: 4, Data: pub}, Payload{Type: 10, Data: random(32)}, Payload{Type: 5, Data: append([]byte{2, 0, 0, 0}, []byte(s.Profile.Hostname+"."+s.Profile.Domain)...)}, Payload{Type: 8, Data: random(hashLen)})
				e.Type = "ike.aggressive"
				e.ASA.IKE.GroupName = eventlog.Printable(id[4:])
			}
		}
		if e.Type != "ike.aggressive" {
			e.Type = "ike.proposal"
		}
		parts = append(parts, s.vendors(p.Version, natt)...)
		response := Encode(p, parts)
		st.Response = response
		st.Request = append([]byte{}, raw...)
		s.sessions[key] = st
		return append([]byte{}, response...)
	}
	if st == nil {
		return nil
	}
	if major == 2 && p.Exchange == 35 && p.MessageID == 1 && st.Keys != nil {
		if !st.Keys.validAuth(raw, p) {
			e.Type = "error"
			e.ASA.Error = "invalid encrypted IKE_AUTH"
			return nil
		}
		st.Done = true
		response := st.Keys.reject(p)
		st.LatestRequest = append([]byte{}, raw...)
		st.LatestResponse = append([]byte{}, response...)
		return response
	}
	if major == 1 && p.Exchange == 2 && Find(p, 4) != nil {
		pub, _, err := dh(st.Group, Find(p, 4))
		if err != nil {
			return notify(p, 16, nil)
		}
		if len(Find(p, 10)) < 8 {
			return nil
		}
		st.Done = true
		response := Encode(p, []Payload{{Type: 4, Data: pub}, {Type: 10, Data: random(32)}})
		st.LatestRequest = append([]byte{}, raw...)
		st.LatestResponse = append([]byte{}, response...)
		return response
	}
	if major == 1 {
		st.Done = true
		return notify(p, 24, nil)
	}
	return nil
}
func (s *Server) Serve(ctx context.Context, c *net.UDPConn, natt bool) error {
	defer c.Close()
	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-ctx.Done():
			c.Close()
		case <-done:
		}
	}()
	buf := make([]byte, MaxPacket+1)
	_, port := eventlog.Peer(c.LocalAddr().String())
	for {
		c.SetReadDeadline(time.Now().Add(time.Second))
		n, peer, err := c.ReadFromUDP(buf)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			if e, ok := err.(net.Error); ok && e.Timeout() {
				s.retransmit(c, natt, port)
				continue
			}
			return err
		}
		b := buf[:n]
		if natt {
			if len(b) == 1 && b[0] == 0xff {
				continue
			}
			if len(b) < 4 || !bytes.Equal(b[:4], []byte{0, 0, 0, 0}) {
				continue
			}
			b = b[4:]
		}
		response := s.Handle(b, peer.String(), port)
		if len(response) > 0 {
			if natt {
				response = append([]byte{0, 0, 0, 0}, response...)
			}
			c.WriteToUDP(response, peer)
		}
		s.retransmit(c, natt, port)
	}
}
func (s *Server) retransmit(c *net.UDPConn, natt bool, port int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	for key, v := range s.sessions {
		if now.Sub(v.Last) > time.Minute {
			delete(s.sessions, key)
			continue
		}
		if v.Done || v.Retries >= 3 || now.Before(v.Next) || !bytes.Contains([]byte(key), []byte("/"+strconv.Itoa(port)+"/")) {
			continue
		}
		peer, err := net.ResolveUDPAddr("udp", v.Peer)
		if err != nil {
			continue
		}
		b := v.Response
		if natt {
			b = append([]byte{0, 0, 0, 0}, b...)
		}
		c.WriteToUDP(b, peer)
		v.Retries++
		v.Next = now.Add(8 * time.Second)
	}
}
