package ike

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"github.com/t3chn0m4g3/ciscoasa_honeypot/internal/eventlog"
	"github.com/t3chn0m4g3/ciscoasa_honeypot/internal/identity"
	"net"
	"path/filepath"
	"testing"
	"time"
)

func testServer(t *testing.T) *Server {
	l, e := eventlog.New(filepath.Join(t.TempDir(), "ike.json"))
	if e != nil {
		t.Fatal(e)
	}
	return New(&identity.Profile{Version: "9.20(4)5", Hostname: "asa", Domain: "example.net"}, l)
}
func v1SA() []byte {
	return []byte{0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 32, 1, 1, 0, 1, 0, 0, 0, 24, 1, 1, 0, 0, 0x80, 1, 0, 5, 0x80, 2, 0, 2, 0x80, 3, 0, 1, 0x80, 4, 0, 2}
}
func TestV1ResponseAndRetransmission(t *testing.T) {
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
		t.Fatal("retransmit changed")
	}
	if s.Handle([]byte{1}, "192.0.2.2:10000", 500) != nil {
		t.Fatal("malformed answered")
	}
	s.mu.Lock()
	for _, v := range s.sessions {
		v.Last = time.Now().Add(-2 * time.Minute)
	}
	s.mu.Unlock()
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
		t.Fatal("IKE_AUTH retransmission changed")
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
