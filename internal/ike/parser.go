// Package ike implements bounded ISAKMP/IKE parsing and a deliberately rejecting responder.
package ike

import (
	"encoding/binary"
	"errors"
	"fmt"
)

const MaxPacket = 65535
const MaxPayloads = 64

type Payload struct {
	Type byte
	Next byte
	Data []byte
}
type Packet struct {
	Initiator [8]byte
	Responder [8]byte
	Version   byte
	Exchange  byte
	Flags     byte
	MessageID uint32
	Payloads  []Payload
}

func Parse(b []byte) (Packet, error) {
	var p Packet
	if len(b) < 28 || len(b) > MaxPacket {
		return p, errors.New("invalid IKE packet size")
	}
	size := int(binary.BigEndian.Uint32(b[24:28]))
	if size != len(b) {
		return p, errors.New("IKE length mismatch")
	}
	copy(p.Initiator[:], b[:8])
	copy(p.Responder[:], b[8:16])
	p.Version = b[17]
	p.Exchange = b[18]
	p.Flags = b[19]
	p.MessageID = binary.BigEndian.Uint32(b[20:24])
	if p.Version>>4 != 1 && p.Version>>4 != 2 {
		return p, errors.New("unsupported IKE version")
	}
	if p.Version>>4 == 1 && p.Flags&1 != 0 {
		p.Payloads = append(p.Payloads, Payload{Type: 255, Data: b[28:]})
		return p, nil
	}
	typ := b[16]
	offset := 28
	for typ != 0 {
		if len(p.Payloads) >= MaxPayloads || offset+4 > len(b) {
			return p, errors.New("invalid payload chain")
		}
		n := int(binary.BigEndian.Uint16(b[offset+2 : offset+4]))
		if n < 4 || offset+n > len(b) {
			return p, errors.New("invalid payload length")
		}
		next := b[offset]
		p.Payloads = append(p.Payloads, Payload{Type: typ, Next: next, Data: b[offset+4 : offset+n]})
		offset += n
		if p.Version>>4 == 2 && typ == 46 {
			return p, nil
		}
		typ = next
	}
	if offset != len(b) {
		return p, errors.New("trailing IKE data")
	}
	return p, nil
}
func Find(p Packet, typ byte) []byte {
	for _, x := range p.Payloads {
		if x.Type == typ {
			return x.Data
		}
	}
	return nil
}
func Encode(p Packet, parts []Payload) []byte {
	b := make([]byte, 28)
	copy(b[:8], p.Initiator[:])
	copy(b[8:16], p.Responder[:])
	if len(parts) > 0 {
		b[16] = parts[0].Type
	}
	b[17] = p.Version
	b[18] = p.Exchange
	b[19] = p.Flags
	binary.BigEndian.PutUint32(b[20:24], p.MessageID)
	for i, x := range parts {
		n := len(x.Data) + 4
		if n > 65535 {
			return nil
		}
		h := []byte{0, 0, 0, 0}
		if i+1 < len(parts) {
			h[0] = parts[i+1].Type
		}
		binary.BigEndian.PutUint16(h[2:], uint16(n))
		b = append(b, h...)
		b = append(b, x.Data...)
	}
	binary.BigEndian.PutUint32(b[24:], uint32(len(b)))
	return b
}
func proposalSummary(p Packet) []string {
	v := Find(p, 1)
	if p.Version>>4 == 2 {
		v = Find(p, 33)
	}
	if v == nil {
		return nil
	}
	if p.Version>>4 == 2 {
		if _, suite, err := selectV2(v); err == nil {
			return []string{fmt.Sprintf("AES-CBC-%d PRF=%d INTEG=%d DH=%d", suite.KeySize*8, suite.PRF, suite.Integrity, suite.DH)}
		}
	} else {
		if _, group, err := selectV1(v); err == nil {
			return []string{fmt.Sprintf("IKEv1 supported proposal DH=%d", group)}
		}
	}
	return []string{fmt.Sprintf("Unselected SA (%d bytes)", len(v))}
}
