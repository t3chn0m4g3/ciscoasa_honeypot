package ike

import (
	"bytes"
	"context"
	"crypto/sha1"
	"crypto/sha256"
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
	Response       []byte
	Request        [32]byte
	LatestRequest  [32]byte
	LatestResponse []byte
	Responder      [8]byte
	Group          uint16
	Keys           *keys
}

const globalRate = 20
const sourceRate = 10
const payloadLog = 1024
const globalBytes = 64 << 10
const sourceBytes = 8 << 10

type endpoint struct {
	IP        string
	Initiator [8]byte
	Responder [8]byte
}
type Server struct {
	Profile   *identity.Profile
	Log       *eventlog.Writer
	mu        sync.Mutex
	sessions  map[string]*session
	rates     map[string]rate
	networks  map[string]rate
	global    rate
	output    rate
	indexed   map[endpoint]string
	summaries *eventlog.Summary
	cleaned   time.Time
	now       func() time.Time
}
type rate struct {
	Start time.Time
	Count int
	Bytes int
}

func New(p *identity.Profile, l *eventlog.Writer) *Server {
	return &Server{Profile: p, Log: l, sessions: map[string]*session{}, rates: map[string]rate{}, networks: map[string]rate{}, indexed: map[endpoint]string{}, summaries: eventlog.NewSummary(l), now: time.Now}
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
	return s.handle(raw, peer, port, port == 4500)
}
func (s *Server) handle(raw []byte, peer string, port int, marker bool) (response []byte) {
	ip, src := eventlog.Peer(peer)
	now := s.now()
	s.maintainAt(now)
	s.mu.Lock()
	defer s.mu.Unlock()
	now = s.now()
	reject := func() {
		s.summaries.Add(eventlog.Event{Type: "ike.ratelimit", SrcIP: ip, DestPort: port, Protocol: "udp", ASA: eventlog.ASA{Profile: eventlog.Profile{Version: s.Profile.Version, Hostname: s.Profile.Hostname}}}, now)
	}
	network := sourceNetwork(ip)
	if !s.admit(ip, network, now) {
		reject()
		return nil
	}
	p, err := Parse(raw)
	if err != nil {
		reject()
		return nil
	}
	e := eventlog.Event{Type: "ike.packet", SrcIP: ip, SrcPort: src, DestPort: port, Protocol: "udp", Payload: eventlog.Bound(eventlog.Printable(raw[:min(len(raw), payloadLog)]), payloadLog), ASA: eventlog.ASA{Profile: eventlog.Profile{Version: s.Profile.Version, Hostname: s.Profile.Hostname}}}
	defer func() {
		if len(response) > 0 && !s.charge(network, ip, len(raw), len(response), marker, now) {
			response = nil
			reject()
			return
		}
		eventlog.Report(s.Log, e)
	}()
	digest := sha256.Sum256(raw)
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
	// NAT-T may change both UDP ports after SA_INIT. Only an authenticated
	// encrypted IKE_AUTH can move an existing SA to its new endpoint.
	if st == nil && major == 2 && p.Exchange == 35 && p.Flags&8 != 0 && p.Flags&0x20 == 0 && p.Responder != ([8]byte{}) {
		oldKey := s.indexed[endpoint{ip, p.Initiator, p.Responder}]
		candidate := s.sessions[oldKey]
		if candidate != nil && candidate.Keys != nil && candidate.Keys.validAuth(raw, p) {
			st = candidate
			delete(s.sessions, oldKey)
			s.sessions[key] = st
			s.indexed[endpoint{ip, p.Initiator, p.Responder}] = key
			st.Peer = peer
		}
	}

	if major == 2 && (p.Flags&0x20 != 0 || p.Flags&8 == 0) {
		return nil
	}
	if st != nil {
		if p.Responder != ([8]byte{}) && p.Responder != st.Responder {
			return nil
		}
		st.Last = now
		if digest == st.LatestRequest {
			return append([]byte{}, st.LatestResponse...)
		}
		p.Responder = st.Responder
	}
	initial := major == 2 && p.Exchange == 34 && p.MessageID == 0 || major == 1 && (p.Exchange == 2 || p.Exchange == 4) && Find(p, 1) != nil
	if initial {
		if st != nil {
			if digest != st.Request {
				return nil
			}
			return append([]byte{}, st.Response...)
		}
		if len(s.sessions) >= 4096 {
			reject()
			return nil
		}
		st = &session{Peer: peer, Last: now}
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
				e.ASA.IKE.GroupName = eventlog.Bound(string(id[4:]), 256)
			}
		}
		if e.Type != "ike.aggressive" {
			e.Type = "ike.proposal"
		}
		if major == 2 {
			requestedNAT := false
			for _, x := range p.Payloads {
				if x.Type == 41 && len(x.Data) >= 4 {
					code := binary.BigEndian.Uint16(x.Data[2:])
					if code == 16388 || code == 16389 {
						requestedNAT = true
					}
				}
			}
			if requestedNAT {
				parts = append(parts, natDetection(p, s.natAddress(net.ParseIP(ip)), port, 16388), natDetection(p, net.ParseIP(ip), src, 16389))
			}
		}
		parts = append(parts, s.vendors(p.Version, natt)...)
		response := Encode(p, parts)
		st.Response = response
		st.Request = digest
		s.sessions[key] = st
		s.indexed[endpoint{ip, p.Initiator, st.Responder}] = key
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
		response := st.Keys.reject(p)
		st.LatestRequest = digest
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
		response := Encode(p, []Payload{{Type: 4, Data: pub}, {Type: 10, Data: random(32)}})
		st.LatestRequest = digest
		st.LatestResponse = append([]byte{}, response...)
		return response
	}
	if major == 1 {
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
		s.maintain()
		c.SetReadDeadline(time.Now().Add(time.Second))
		n, peer, err := c.ReadFromUDP(buf)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			if e, ok := err.(net.Error); ok && e.Timeout() {
				s.maintain()
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
		response := s.handle(b, peer.String(), port, natt)
		if len(response) > 0 {
			if natt {
				response = append([]byte{0, 0, 0, 0}, response...)
			}
			c.WriteToUDP(response, peer)
		}
		s.maintain()
	}
}
func sourceNetwork(ip string) string {
	address := net.ParseIP(ip)
	if v4 := address.To4(); v4 != nil {
		return v4.Mask(net.CIDRMask(24, 32)).String() + "/24"
	}
	if address != nil {
		return address.Mask(net.CIDRMask(64, 128)).String() + "/64"
	}
	return "unknown"
}
func window(r rate, now time.Time) rate {
	start := now.Truncate(time.Second)
	if !r.Start.Equal(start) {
		return rate{Start: start}
	}
	return r
}
func (s *Server) admit(ip, network string, now time.Time) bool {
	s.global = window(s.global, now)
	s.output = window(s.output, now)
	r := window(s.rates[ip], now)
	n := window(s.networks[network], now)
	if s.global.Count >= globalRate || r.Count >= 20 || n.Count >= sourceRate || s.output.Bytes > globalBytes-2048 || n.Bytes > sourceBytes-2048 {
		return false
	}
	if _, ok := s.rates[ip]; !ok && len(s.rates) >= 4096 {
		return false
	}
	if _, ok := s.networks[network]; !ok && len(s.networks) >= 4096 {
		return false
	}
	s.global.Count++
	r.Count++
	n.Count++
	s.rates[ip] = r
	s.networks[network] = n
	return true
}
func (s *Server) charge(network, ip string, request, response int, marker bool, now time.Time) bool {
	overhead := 28
	if net.ParseIP(ip).To4() == nil {
		overhead = 48
	}
	if marker {
		overhead += 4
	}
	size := response + overhead
	n := window(s.networks[network], now)
	s.output = window(s.output, now)
	if size > 3*(request+overhead) || s.output.Bytes+size > globalBytes || n.Bytes+size > sourceBytes {
		return false
	}
	s.output.Bytes += size
	n.Bytes += size
	s.networks[network] = n
	return true
}
func (s *Server) maintain() { s.maintainAt(s.now()) }
func (s *Server) maintainAt(now time.Time) {
	s.mu.Lock()
	if now.Sub(s.cleaned) < time.Second {
		s.mu.Unlock()
		return
	}
	s.cleaned = now
	for k, v := range s.sessions {
		if now.Sub(v.Last) > time.Minute {
			ip, _ := eventlog.Peer(v.Peer)
			var spi [8]byte
			if len(v.Response) >= 8 {
				copy(spi[:], v.Response[:8])
			}
			delete(s.indexed, endpoint{ip, spi, v.Responder})
			delete(s.sessions, k)
		}
	}
	for k, v := range s.rates {
		if now.Sub(v.Start) > time.Second {
			delete(s.rates, k)
		}
	}
	for k, v := range s.networks {
		if now.Sub(v.Start) > time.Second {
			delete(s.networks, k)
		}
	}
	s.mu.Unlock()
	s.summaries.Tick(now)
}
func (s *Server) natAddress(peer net.IP) net.IP {
	h := sha256.Sum256([]byte(s.Profile.ConfigHash + "/" + s.Profile.Hostname + "/" + s.Profile.Domain))
	if peer.To4() != nil {
		return net.IPv4(10, h[0], h[1], 1+h[2]%254)
	}
	b := append(net.IP(nil), h[:16]...)
	b[0] = 0xfd
	return b
}
func natDetection(p Packet, ip net.IP, port int, code uint16) Payload {
	data := append(append([]byte{}, p.Initiator[:]...), p.Responder[:]...)
	if v4 := ip.To4(); v4 != nil {
		ip = v4
	}
	data = append(data, ip...)
	data = append(data, byte(port>>8), byte(port))
	digest := sha1.Sum(data)
	b := []byte{0, 0, byte(code >> 8), byte(code)}
	b = append(b, digest[:]...)
	return Payload{Type: 41, Data: b}
}
