package identity

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"regexp"
	"time"
)

type Group struct {
	Name  string `json:"name"`
	Alias string `json:"alias"`
}
type Profile struct {
	Version     string  `json:"version"`
	Hostname    string  `json:"hostname"`
	Domain      string  `json:"domain"`
	Groups      []Group `json:"groups"`
	Banner      string  `json:"banner"`
	ConfigHash  string  `json:"config_hash"`
	Certificate string  `json:"certificate"`
	PrivateKey  string  `json:"private_key"`
}

func Token(n int) string {
	b := make([]byte, n)
	if _, e := rand.Read(b); e != nil {
		panic(e)
	}
	return hex.EncodeToString(b)
}
func pick(n int) int {
	v, e := rand.Int(rand.Reader, big.NewInt(int64(n)))
	if e != nil {
		panic(e)
	}
	return int(v.Int64())
}
func (p *Profile) Validate() error {
	if len(p.Version) > 64 || !regexp.MustCompile(`^9\.(16|18|20|22|23|24)\([0-9]+\)[0-9]*$`).MatchString(p.Version) {
		return errors.New("invalid ASA version")
	}
	host := regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9.-]{0,252}$`)
	if !host.MatchString(p.Hostname) || !host.MatchString(p.Domain) {
		return errors.New("invalid hostname or domain")
	}
	if len(p.Groups) < 2 || len(p.Groups) > 4 || len(p.Banner) > 2048 || len(p.ConfigHash) > 128 {
		return errors.New("invalid profile fields")
	}
	for _, g := range p.Groups {
		if g.Name == "" || len(g.Name) > 128 || g.Alias == "" || len(g.Alias) > 128 {
			return errors.New("invalid tunnel group")
		}
	}
	_, e := tls.X509KeyPair([]byte(p.Certificate), []byte(p.PrivateKey))
	return e
}
func Load(path string) (*Profile, error) {
	b, e := os.ReadFile(path)
	if e == nil {
		if len(b) > 64*1024 {
			return nil, errors.New("identity exceeds 64 KiB")
		}
		var p Profile
		if e = json.Unmarshal(b, &p); e != nil {
			return nil, fmt.Errorf("identity: %w", e)
		}
		return &p, p.Validate()
	}
	if !errors.Is(e, os.ErrNotExist) {
		return nil, e
	}
	// Weighted toward pre-fix releases; the same profile drives all protocols.
	versions := []string{"9.16(4)80", "9.18(4)60", "9.18(4)60", "9.20(4)5", "9.20(4)5", "9.22(2)10", "9.23(1)15", "9.24(1)"}
	p := &Profile{Version: versions[pick(len(versions))], Hostname: []string{"asa", "vpn", "edge"}[pick(3)] + "-" + Token(2), Domain: []string{"corp.local", "example.net", "vpn.local"}[pick(3)], Banner: "Authorized access only.", ConfigHash: Token(8)}
	gs := []Group{{"RemoteAccess", "Remote Access"}, {"Employees", "Employees"}, {"Contractors", "Contractors"}, {"SSLClientProfile", "SSL VPN"}, {"VPN", "VPN"}, {"Vendors", "Vendors"}}
	for i := len(gs) - 1; i > 0; i-- {
		j := pick(i + 1)
		gs[i], gs[j] = gs[j], gs[i]
	}
	p.Groups = gs[:2+pick(3)]
	key, e := rsa.GenerateKey(rand.Reader, 2048)
	if e != nil {
		return nil, e
	}
	serial, e := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if e != nil {
		return nil, e
	}
	cn := p.Hostname + "." + p.Domain
	if pick(3) != 0 {
		cn = "ASA Temporary Self Signed Certificate"
	}
	cert := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: cn}, NotBefore: time.Now().Add(-24 * time.Hour), NotAfter: time.Now().AddDate(10, 0, 0), KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, DNSNames: []string{p.Hostname + "." + p.Domain}}
	der, e := x509.CreateCertificate(rand.Reader, cert, cert, &key.PublicKey, key)
	if e != nil {
		return nil, e
	}
	p.Certificate = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	p.PrivateKey = string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}))
	if e = p.Validate(); e != nil {
		return nil, e
	}
	if e = os.MkdirAll(filepath.Dir(path), 0700); e != nil {
		return nil, e
	}
	f, e := os.CreateTemp(filepath.Dir(path), ".identity-")
	if e != nil {
		return nil, e
	}
	defer os.Remove(f.Name())
	b, e = json.MarshalIndent(p, "", "  ")
	if e == nil {
		_, e = f.Write(append(b, '\n'))
	}
	if e == nil {
		e = f.Sync()
	}
	ce := f.Close()
	if e == nil {
		e = ce
	}
	if e != nil {
		return nil, e
	}
	// Link is atomic and does not overwrite an identity another process created.
	if e = os.Link(f.Name(), path); errors.Is(e, os.ErrExist) {
		return Load(path)
	}
	return p, e
}
func (p *Profile) PreChainFix() bool {
	var minor, rev, interim int
	fmt.Sscanf(p.Version, "9.%d(%d)%d", &minor, &rev, &interim)
	fix := map[int][2]int{16: {4, 85}, 18: {4, 67}, 20: {4, 10}, 22: {2, 14}, 23: {1, 19}}
	v, ok := fix[minor]
	return ok && (rev < v[0] || (rev == v[0] && interim < v[1]))
}
