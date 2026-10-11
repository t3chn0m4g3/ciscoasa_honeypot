package ike

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"github.com/t3chn0m4g3/ciscoasa_honeypot/internal/eventlog"
	"github.com/t3chn0m4g3/ciscoasa_honeypot/internal/identity"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

var testPaths sync.Map

func testServer(t *testing.T) *Server {
	path := filepath.Join(t.TempDir(), "ike.json")
	l, e := eventlog.New(path)
	if e != nil {
		t.Fatal(e)
	}
	s := New(&identity.Profile{Version: "9.20(4)5", Hostname: "asa", Domain: "example.net"}, l)
	testPaths.Store(s, path)
	t.Cleanup(func() { l.Close(); testPaths.Delete(s) })
	return s
}
func v1SA() []byte {
	return []byte{0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 32, 1, 1, 0, 1, 0, 0, 0, 24, 1, 1, 0, 0, 0x80, 1, 0, 5, 0x80, 2, 0, 2, 0x80, 3, 0, 1, 0x80, 4, 0, 2}
}
func TestV1ResponseAndRepeatedRequest(t *testing.T) {
	s := testServer(t)
	p := Packet{Version: 0x10, Exchange: 2}
	p.Initiator[0] = 1
	b := Encode(p, []Payload{{Type: 1, Data: v1SA()}})
	resp := s.Handle(b, "192.0.2.1:10000", 500)
	r, e := Parse(resp)
	if e != nil {
		t.Fatal(e)
	}
	if r.Responder == ([8]byte{}) || Find(r, 13) == nil {
		t.Fatal(r)
	}
	if !bytes.Equal(resp, s.Handle(b, "192.0.2.1:10000", 500)) {
		t.Fatal("repeated request changed the response")
	}
	if s.Handle([]byte{1}, "192.0.2.2:10000", 500) != nil {
		t.Fatal("malformed answered")
	}
	s.mu.Lock()
	for _, v := range s.sessions {
		v.Last = time.Now().Add(-2 * time.Minute)
	}
	s.cleaned = time.Time{}
	s.mu.Unlock()
	s.maintain()
	p.Initiator[0] = 2
	s.Handle(Encode(p, []Payload{{Type: 1, Data: v1SA()}}), "192.0.2.3:10000", 500)
	if len(s.sessions) != 1 {
		t.Fatal(len(s.sessions))
	}
}
func v2SA() []byte {
	ts := [][]byte{transform(1, 12, 128), transform(2, 5, 0), transform(3, 12, 0), transform(4, 14, 0)}
	b := []byte{0, 0, 0, 0, 1, 1, 0, 4}
	for i, x := range ts {
		if i < 3 {
			x[0] = 3
		}
		b = append(b, x...)
	}
	binary.BigEndian.PutUint16(b[2:], uint16(len(b)))
	return b
}
func TestV2EncryptedAuthFailure(t *testing.T) {
	s := testServer(t)
	p := Packet{Version: 0x20, Exchange: 34, Flags: 8}
	p.Initiator[0] = 3
	peer := make([]byte, 256)
	peer[255] = 2
	b := Encode(p, []Payload{{Type: 33, Data: v2SA()}, {Type: 34, Data: append([]byte{0, 14, 0, 0}, peer...)}, {Type: 40, Data: random(32)}, natDetection(p, net.IPv4(192, 0, 2, 1), 12345, 16388)})
	resp := s.Handle(b, "192.0.2.1:12345", 500)
	rp, e := Parse(resp)
	if e != nil {
		t.Fatal(e)
	}
	if notify := Find(rp, 41); len(notify) != 24 || binary.BigEndian.Uint16(notify[2:]) != 16388 {
		t.Fatal("NAT detection missing", notify)
	}
	if Find(rp, 34) == nil {
		t.Fatal(rp)
	}
	var k keys
	for _, v := range s.sessions {
		k = *v.Keys
	}
	p.Responder = rp.Responder
	p.Exchange = 35
	p.MessageID = 1
	plain := make([]byte, 16)
	plain[15] = 7
	iv := random(16)
	block, _ := aes.NewCipher(k.ei)
	encrypted := make([]byte, 16)
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(encrypted, plain)
	b = Encode(p, []Payload{{Type: 46, Data: append(append(iv, encrypted...), make([]byte, k.icvlen())...)}})
	b[28] = 35
	mac := prf(k.integrityHash(), k.ai, b[:len(b)-k.icvlen()])
	copy(b[len(b)-k.icvlen():], mac[:k.icvlen()])
	resp = s.Handle(b, "192.0.2.1:12345", 500)
	rp, e = Parse(resp)
	if e != nil || Find(rp, 46) == nil {
		t.Fatal(e, rp)
	}
	if !bytes.Equal(resp, s.Handle(b, "192.0.2.1:12345", 500)) {
		t.Fatal("IKE_AUTH repeated response changed")
	}
	invalid := append([]byte{}, b...)
	invalid[len(invalid)-1] ^= 1
	if s.Handle(invalid, "192.0.2.1:55555", 4500) != nil {
		t.Fatal("unauthenticated NAT-T migration accepted")
	}
	// Move the same authenticated SA to NAT-T and a different source port.
	if !bytes.Equal(resp, s.Handle(b, "192.0.2.1:54321", 4500)) {
		t.Fatal("NAT-T port floating lost the SA")
	}
	data := Find(rp, 46)
	block, _ = aes.NewCipher(k.er)
	cipher.NewCBCDecrypter(block, data[:16]).CryptBlocks(plain, data[16:32])
	if binary.BigEndian.Uint16(plain[6:8]) != 24 {
		t.Fatal(plain)
	}
	b[len(b)-1] ^= 1
	if s.Handle(b, "192.0.2.1:12345", 500) != nil {
		t.Fatal("bad MAC accepted")
	}
}
func TestNATMarker(t *testing.T) {
	s := testServer(t)
	c, e := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if e != nil {
		t.Fatal(e)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- s.Serve(ctx, c, true) }()
	client, e := net.DialUDP("udp", nil, c.LocalAddr().(*net.UDPAddr))
	if e != nil {
		t.Fatal(e)
	}
	defer client.Close()
	p := Packet{Version: 0x10, Exchange: 2}
	p.Initiator[0] = 1
	b := append([]byte{0, 0, 0, 0}, Encode(p, []Payload{{Type: 1, Data: v1SA()}})...)
	client.SetDeadline(time.Now().Add(time.Second))
	client.Write(b)
	buf := make([]byte, 2048)
	n, e := client.Read(buf)
	if e != nil || n < 4 || !bytes.Equal(buf[:4], []byte{0, 0, 0, 0}) {
		t.Fatal(n, e)
	}
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("shutdown blocked")
	}
}
func FuzzParse(f *testing.F) {
	f.Add(Encode(Packet{Version: 0x10, Exchange: 2}, []Payload{{Type: 1, Data: v1SA()}}))
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, b []byte) {
		p, e := Parse(b)
		if e == nil {
			Encode(p, p.Payloads)
		}
	})
}

func TestCiscoVendorOrdering(t *testing.T) {
	s := testServer(t)
	parts := s.vendors(0x10, true)
	want := []string{"12f5f28c457168a9702d9fe274cc0100", "09002689dfd6b712", "4048b7d56ebce88525e7de7f00d6c2d3c0000000", "1f07f70eaa6514d3b0fa96542a140405", "afcad71368a1f1c96b8696fc77570100", "4a131c81070358455c5728f20e95452f"}
	if len(parts) != len(want) {
		t.Fatal(parts)
	}
	for i, x := range parts {
		if !bytes.Equal(x.Data, vid(want[i])) {
			t.Fatal(i, x.Data)
		}
	}
}

func TestNATDetectionHashes(t *testing.T) {
	p := Packet{Version: 0x20}
	p.Initiator[0] = 1
	p.Responder[0] = 2
	x := natDetection(p, net.IPv4(192, 0, 2, 1), 500, 16388)
	if x.Type != 41 || len(x.Data) != 24 || binary.BigEndian.Uint16(x.Data[2:]) != 16388 {
		t.Fatal(x)
	}
	y := natDetection(p, net.IPv4(192, 0, 2, 1), 4500, 16388)
	if bytes.Equal(x.Data, y.Data) {
		t.Fatal("NAT detection ignored port")
	}
}

func TestEachRequestAnsweredOnce(t *testing.T) {
	for _, version := range []byte{0x10, 0x20} {
		t.Run(fmt.Sprintf("version-%x", version), func(t *testing.T) {
			t.Parallel()
			s := testServer(t)
			c, e := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
			if e != nil {
				t.Fatal(e)
			}
			ctx, cancel := context.WithCancel(context.Background())
			done := make(chan error, 1)
			go func() { done <- s.Serve(ctx, c, false) }()
			defer func() { cancel(); <-done }()
			client, e := net.DialUDP("udp", nil, c.LocalAddr().(*net.UDPAddr))
			if e != nil {
				t.Fatal(e)
			}
			defer client.Close()
			p := Packet{Version: version, Exchange: 2}
			p.Initiator[0] = 7
			parts := []Payload{{Type: 1, Data: v1SA()}}
			if version == 0x20 {
				p.Exchange = 34
				p.Flags = 8
				peer := make([]byte, 256)
				peer[255] = 2
				parts = []Payload{{Type: 33, Data: v2SA()}, {Type: 34, Data: append([]byte{0, 14, 0, 0}, peer...)}, {Type: 40, Data: random(32)}}
			}
			request := Encode(p, parts)
			client.SetDeadline(time.Now().Add(time.Second))
			client.Write(request)
			buf := make([]byte, 2048)
			n, e := client.Read(buf)
			if e != nil {
				t.Fatal(e)
			}
			first := append([]byte(nil), buf[:n]...)
			client.SetReadDeadline(time.Now().Add(30 * time.Second))
			if n, e := client.Read(buf); e == nil {
				t.Fatal("second datagram", n)
			}
			client.SetDeadline(time.Now().Add(time.Second))
			client.Write(request)
			n, e = client.Read(buf)
			if e != nil || !bytes.Equal(buf[:n], first) {
				t.Fatal("repeated response", n, e)
			}
		})
	}
}

func events(t *testing.T, s *Server) []eventlog.Event {
	t.Helper()
	path, _ := testPaths.Load(s)
	b, _ := os.ReadFile(path.(string))
	var out []eventlog.Event
	for _, line := range bytes.Split(bytes.TrimSpace(b), []byte("\n")) {
		var e eventlog.Event
		if json.Unmarshal(line, &e) == nil {
			out = append(out, e)
		}
	}
	return out
}

func TestPacketBudgetAndSummary(t *testing.T) {
	s := testServer(t)
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	s.now = func() time.Time { return now }
	answered := 0
	for i := 0; i < 25; i++ {
		p := Packet{Version: 0x10, Exchange: 2}
		p.Initiator[0] = byte(i + 1)
		if s.Handle(Encode(p, []Payload{{Type: 1, Data: v1SA()}}), fmt.Sprintf("198.51.%d.1:500", i), 500) != nil {
			answered++
		}
	}
	if answered != globalRate {
		t.Fatal(answered)
	}
	s.mu.Lock()
	s.cleaned = time.Time{}
	s.mu.Unlock()
	s.maintainAt(now.Add(time.Minute))
	got := events(t, s)
	if len(got) != 25 {
		t.Fatal(len(got))
	}
	count := 0
	for _, e := range got {
		if e.Type == "ike.ratelimit" {
			if e.ASA.Count != 1 || e.DestPort != 500 {
				t.Fatal(e)
			}
			count++
		}
	}
	if count != 25-globalRate {
		t.Fatal(count)
	}
}

func TestSourceNetworkBudget(t *testing.T) {
	s := testServer(t)
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	s.now = func() time.Time { return now }
	answered := 0
	for i := 0; i < 15; i++ {
		p := Packet{Version: 0x10, Exchange: 2}
		p.Initiator[0] = byte(i + 1)
		if s.Handle(Encode(p, []Payload{{Type: 1, Data: v1SA()}}), fmt.Sprintf("203.0.113.%d:500", i+1), 500) != nil {
			answered++
		}
	}
	if answered != sourceRate {
		t.Fatal(answered)
	}
}

func TestLoggedPacketPayloadBounded(t *testing.T) {
	s := testServer(t)
	p := Packet{Version: 0x10, Exchange: 5}
	s.Handle(Encode(p, []Payload{{Type: 13, Data: bytes.Repeat([]byte("<"), 4000)}}), "192.0.2.9:500", 500)
	got := events(t, s)
	if len(got) != 1 || len(got[0].Payload) > payloadLog {
		t.Fatal(len(got), len(got[0].Payload))
	}
}

func TestNATAddressFromProfile(t *testing.T) {
	s := testServer(t)
	a := s.natAddress(net.IPv4(192, 0, 2, 1))
	if a.To4() == nil || a.To4()[0] != 10 || !a.Equal(s.natAddress(net.IPv4(198, 51, 100, 1))) {
		t.Fatal(a)
	}
	if b := s.natAddress(net.ParseIP("2001:db8::1")); b.To4() != nil || b[0] != 0xfd {
		t.Fatal(b)
	}
}

func TestResponseByteWindows(t *testing.T) {
	s := testServer(t)
	now := time.Now()
	network := sourceNetwork("192.0.2.1")
	if s.charge(network, "192.0.2.1", 40, 400, false, now) {
		t.Fatal("response size")
	}
	s.networks[network] = rate{Start: now.Truncate(time.Second), Bytes: sourceBytes - 100}
	if s.charge(network, "192.0.2.1", 1000, 100, false, now) {
		t.Fatal("network bytes")
	}
	s.output = rate{Start: now.Truncate(time.Second), Bytes: globalBytes - 100}
	if s.charge(sourceNetwork("198.51.100.1"), "198.51.100.1", 1000, 100, true, now) {
		t.Fatal("global bytes")
	}
	if !s.charge(network, "192.0.2.1", 1000, 100, true, now.Add(time.Second)) {
		t.Fatal("new second")
	}
	if sourceNetwork("2001:db8:1::1") != sourceNetwork("2001:db8:1::2") {
		t.Fatal("IPv6 network")
	}
}

func TestSummaryWindowAndCapacity(t *testing.T) {
	s := testServer(t)
	now := time.Now()
	for i := 0; i < 1000; i++ {
		s.summaries.Add(eventlog.Event{Type: "ike.ratelimit", SrcIP: "192.0.2.1", DestPort: 500}, now)
	}
	s.summaries.Tick(now.Add(59 * time.Second))
	if len(events(t, s)) != 0 {
		t.Fatal("early line")
	}
	s.summaries.Tick(now.Add(time.Minute))
	got := events(t, s)
	if len(got) != 1 || got[0].ASA.Count != 1000 {
		t.Fatal(got)
	}
	s.summaries.Tick(now.Add(2 * time.Minute))
	if len(events(t, s)) != 1 {
		t.Fatal("extra line")
	}
	for i := 0; i < 5000; i++ {
		s.summaries.Add(eventlog.Event{Type: "ike.ratelimit", SrcIP: fmt.Sprint(i), DestPort: 500}, now)
	}
	s.summaries.Tick(now.Add(3 * time.Minute))
	if len(events(t, s)) != eventlog.SummaryLimit+2 {
		t.Fatal(len(events(t, s)))
	}
}

func TestSessionRequestHashesAndCapacity(t *testing.T) {
	s := testServer(t)
	p := Packet{Version: 0x10, Exchange: 2}
	p.Initiator[0] = 1
	request := Encode(p, []Payload{{Type: 1, Data: v1SA()}})
	if s.Handle(request, "192.0.2.1:12345", 500) == nil {
		t.Fatal("first response")
	}
	for _, v := range s.sessions {
		if v.Request != sha256.Sum256(request) || len(v.Request) != 32 || len(v.LatestRequest) != 32 {
			t.Fatal("request hash")
		}
	}
	for i := len(s.sessions); i < 4096; i++ {
		s.sessions[fmt.Sprint(i)] = &session{Last: time.Now()}
	}
	p.Initiator[0] = 2
	if s.Handle(Encode(p, []Payload{{Type: 1, Data: v1SA()}}), "198.51.100.1:12345", 500) != nil {
		t.Fatal("session count")
	}
	if len(s.sessions) != 4096 {
		t.Fatal(len(s.sessions))
	}
}

func TestPacketWindowAdvance(t *testing.T) {
	s := testServer(t)
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	s.now = func() time.Time { return now }
	p := Packet{Version: 0x10, Exchange: 2}
	p.Initiator[0] = 1
	request := Encode(p, []Payload{{Type: 1, Data: v1SA()}})
	for i := 0; i < sourceRate; i++ {
		if s.Handle(request, "192.0.2.1:500", 500) == nil {
			t.Fatal(i)
		}
	}
	if s.Handle(request, "192.0.2.1:500", 500) != nil {
		t.Fatal("current window")
	}
	now = now.Add(time.Second)
	if s.Handle(request, "192.0.2.1:500", 500) == nil {
		t.Fatal("next window")
	}
}
