package ike

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"hash"
	"math/big"
)

const prime2 = "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381FFFFFFFFFFFFFFFF"
const prime14 = "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF"

func random(n int) []byte {
	b := make([]byte, n)
	if _, e := rand.Read(b); e != nil {
		panic(e)
	}
	return b
}
func dh(group uint16, peer []byte) (public, shared []byte, err error) {
	s := ""
	switch group {
	case 2:
		s = prime2
	case 14:
		s = prime14
	default:
		return nil, nil, errors.New("unsupported DH group")
	}
	p, _ := new(big.Int).SetString(s, 16)
	n := (p.BitLen() + 7) / 8
	if len(peer) != n {
		return nil, nil, errors.New("invalid KE length")
	}
	y := new(big.Int).SetBytes(peer)
	max := new(big.Int).Sub(p, big.NewInt(2))
	if y.Cmp(big.NewInt(2)) < 0 || y.Cmp(max) > 0 {
		return nil, nil, errors.New("invalid KE value")
	}
	priv := new(big.Int).SetBytes(random(32))
	pub := new(big.Int).Exp(big.NewInt(2), priv, p)
	secret := new(big.Int).Exp(y, priv, p)
	return pub.FillBytes(make([]byte, n)), secret.FillBytes(make([]byte, n)), nil
}

type suite struct {
	KeySize   int
	PRF       uint16
	Integrity uint16
	DH        uint16
}

func (s suite) hash() func() hash.Hash {
	if s.PRF == 2 {
		return sha1.New
	}
	return sha256.New
}
func prf(f func() hash.Hash, key, data []byte) []byte {
	m := hmac.New(f, key)
	m.Write(data)
	return m.Sum(nil)
}
func expand(f func() hash.Hash, key, seed []byte, n int) []byte {
	out, t := []byte{}, []byte{}
	for i := byte(1); len(out) < n; i++ {
		b := append(append(append([]byte{}, t...), seed...), i)
		t = prf(f, key, b)
		out = append(out, t...)
	}
	return out[:n]
}

type keys struct {
	suite          suite
	ai, ar, ei, er []byte
}

func derive(s suite, ni, nr, secret []byte, init, responder [8]byte) keys {
	seed := append(append(append(append([]byte{}, ni...), nr...), init[:]...), responder[:]...)
	f := s.hash()
	skey := prf(f, append(append([]byte{}, ni...), nr...), secret)
	prflen := f().Size()
	authlen := 32
	if s.Integrity == 2 {
		authlen = 20
	}
	material := expand(f, skey, seed, prflen+2*authlen+2*s.KeySize+2*prflen)
	i := prflen
	k := keys{suite: s}
	k.ai = material[i : i+authlen]
	i += authlen
	k.ar = material[i : i+authlen]
	i += authlen
	k.ei = material[i : i+s.KeySize]
	i += s.KeySize
	k.er = material[i : i+s.KeySize]
	return k
}
func (k keys) integrityHash() func() hash.Hash {
	if k.suite.Integrity == 2 {
		return sha1.New
	}
	return sha256.New
}
func (k keys) icvlen() int {
	if k.suite.Integrity == 2 {
		return 12
	}
	return 16
}
func (k keys) validAuth(raw []byte, p Packet) bool {
	data := Find(p, 46)
	icv := k.icvlen()
	if len(data) < 16+16+icv {
		return false
	}
	mac := prf(k.integrityHash(), k.ai, raw[:len(raw)-icv])
	if !hmac.Equal(mac[:icv], raw[len(raw)-icv:]) {
		return false
	}
	enc := data[16 : len(data)-icv]
	if len(enc)%aes.BlockSize != 0 {
		return false
	}
	block, e := aes.NewCipher(k.ei)
	if e != nil {
		return false
	}
	plain := make([]byte, len(enc))
	cipher.NewCBCDecrypter(block, data[:16]).CryptBlocks(plain, enc)
	pad := int(plain[len(plain)-1]) + 1
	return pad <= len(plain)
}
func (k keys) reject(p Packet) []byte {
	p.Flags = 0x20
	inner := []byte{0, 0, 0, 8, 0, 0, 0, 24}
	padding := (16 - ((len(inner) + 1) % 16)) % 16
	plain := append(inner, make([]byte, padding)...)
	plain = append(plain, byte(padding))
	iv := random(16)
	block, _ := aes.NewCipher(k.er)
	enc := make([]byte, len(plain))
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(enc, plain)
	data := append(append(iv, enc...), make([]byte, k.icvlen())...)
	raw := Encode(p, []Payload{{Type: 46, Data: data}})
	raw[28] = 41
	mac := prf(k.integrityHash(), k.ar, raw[:len(raw)-k.icvlen()])
	copy(raw[len(raw)-k.icvlen():], mac[:k.icvlen()])
	return raw
}
func vid(hexString string) []byte { b, _ := hex.DecodeString(hexString); return b }
func transform(typ byte, id uint16, keybits int) []byte {
	n := 8
	if keybits > 0 {
		n += 4
	}
	b := make([]byte, n)
	binary.BigEndian.PutUint16(b[2:], uint16(n))
	b[4] = typ
	binary.BigEndian.PutUint16(b[6:], id)
	if keybits > 0 {
		binary.BigEndian.PutUint16(b[8:], 0x800e)
		binary.BigEndian.PutUint16(b[10:], uint16(keybits))
	}
	return b
}
func selectV2(sa []byte) ([]byte, suite, error) {
	for off, count := 0, 0; off < len(sa) && count < 16; count++ {
		if off+8 > len(sa) {
			break
		}
		n := int(binary.BigEndian.Uint16(sa[off+2:]))
		if n < 8 || off+n > len(sa) {
			break
		}
		proposal := sa[off : off+n]
		spi := int(proposal[6])
		if proposal[5] != 1 || spi != 0 {
			off += n
			continue
		}
		choices := map[byte][]uint16{}
		keysize := map[uint16]int{}
		for i, tcount := 8+spi, 0; i < len(proposal) && tcount < 32; tcount++ {
			if i+8 > len(proposal) {
				break
			}
			tn := int(binary.BigEndian.Uint16(proposal[i+2:]))
			if tn < 8 || i+tn > len(proposal) {
				break
			}
			t := proposal[i : i+tn]
			id := binary.BigEndian.Uint16(t[6:])
			choices[t[4]] = append(choices[t[4]], id)
			if t[4] == 1 && id == 12 {
				for a := 8; a+4 <= len(t); a += 4 {
					if binary.BigEndian.Uint16(t[a:]) == 0x800e {
						bits := int(binary.BigEndian.Uint16(t[a+2:]))
						if bits == 128 || bits == 256 {
							keysize[id] = bits / 8
						}
					}
				}
			}
			i += tn
		}
		has := func(typ byte, id uint16) bool {
			for _, v := range choices[typ] {
				if v == id {
					return true
				}
			}
			return false
		}
		s := suite{KeySize: keysize[12]}
		for _, v := range []uint16{5, 2} {
			if has(2, v) {
				s.PRF = v
				break
			}
		}
		for _, v := range []uint16{12, 2} {
			if has(3, v) {
				s.Integrity = v
				break
			}
		}
		for _, v := range []uint16{14, 2} {
			if has(4, v) {
				s.DH = v
				break
			}
		}
		if s.KeySize > 0 && s.PRF != 0 && s.Integrity != 0 && s.DH != 0 {
			ts := [][]byte{transform(1, 12, s.KeySize*8), transform(2, s.PRF, 0), transform(3, s.Integrity, 0), transform(4, s.DH, 0)}
			out := []byte{0, 0, 0, 0, proposal[4], 1, 0, 4}
			for i, t := range ts {
				if i < 3 {
					t[0] = 3
				}
				out = append(out, t...)
			}
			binary.BigEndian.PutUint16(out[2:], uint16(len(out)))
			return out, s, nil
		}
		off += n
	}
	return nil, suite{}, errors.New("no supported proposal")
}
func selectV1(sa []byte) ([]byte, uint16, error) {
	if len(sa) < 8 || binary.BigEndian.Uint32(sa[:4]) != 1 {
		return nil, 0, errors.New("invalid DOI")
	}
	for off, count := 8, 0; off+8 <= len(sa) && count < 16; count++ {
		n := int(binary.BigEndian.Uint16(sa[off+2:]))
		if n < 8 || off+n > len(sa) {
			break
		}
		p := sa[off : off+n]
		if p[5] != 1 || p[6] != 0 {
			off += n
			continue
		}
		for i, c := 8, 0; i+8 <= len(p) && c < 32; c++ {
			tn := int(binary.BigEndian.Uint16(p[i+2:]))
			if tn < 8 || i+tn > len(p) {
				break
			}
			t := p[i : i+tn]
			attrs := map[uint16]uint16{}
			valid := t[5] == 1
			for a := 8; a < len(t); {
				if a+4 > len(t) {
					valid = false
					break
				}
				kind := binary.BigEndian.Uint16(t[a:])
				value := binary.BigEndian.Uint16(t[a+2:])
				if kind&0x8000 != 0 {
					attrs[kind&0x7fff] = value
					a += 4
				} else {
					if a+4+int(value) > len(t) {
						valid = false
						break
					}
					a += 4 + int(value)
				}
			}
			group := attrs[4]
			if valid && (attrs[1] == 7 || attrs[1] == 5) && (attrs[2] == 2 || attrs[2] == 4) && (attrs[3] == 1 || attrs[3] == 65001) && (group == 2 || group == 14) {
				out := append([]byte{}, sa[:8]...)
				pr := append([]byte{}, p[:8]...)
				pr[0] = 0
				pr[7] = 1
				tr := append([]byte{}, t...)
				tr[0] = 0
				tr[4] = 1
				binary.BigEndian.PutUint16(pr[2:], uint16(len(pr)+len(tr)))
				out = append(out, pr...)
				out = append(out, tr...)
				return out, group, nil
			}
			i += tn
		}
		off += n
	}
	return nil, 0, errors.New("no supported proposal")
}
