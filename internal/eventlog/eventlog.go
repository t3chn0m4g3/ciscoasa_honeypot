// Package eventlog writes bounded JSON lines without interpreting attacker text.
package eventlog

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"
)

type HTTP struct {
	Method    string `json:"method"`
	URI       string `json:"uri"`
	UserAgent string `json:"user_agent"`
}
type Client struct {
	Version  string `json:"version,omitempty"`
	Platform string `json:"platform,omitempty"`
	DeviceID string `json:"device_id,omitempty"`
}
type IKE struct {
	Version   string   `json:"version"`
	Exchange  string   `json:"exchange"`
	GroupName string   `json:"group_name,omitempty"`
	VendorIDs []string `json:"vendor_ids,omitempty"`
	Proposals []string `json:"proposals,omitempty"`
}
type Upload struct {
	SHA256 string `json:"sha256"`
	Size   int64  `json:"size"`
	File   string `json:"file,omitempty"`
	Stored bool   `json:"stored"`
}
type Profile struct {
	Version  string `json:"version"`
	Hostname string `json:"hostname"`
}
type ASA struct {
	HTTP       *HTTP   `json:"http,omitempty"`
	Group      string  `json:"group,omitempty"`
	Client     *Client `json:"client,omitempty"`
	IKE        *IKE    `json:"ike,omitempty"`
	Upload     *Upload `json:"upload,omitempty"`
	Profile    Profile `json:"profile"`
	Error      string  `json:"error,omitempty"`
	Anomaly    string  `json:"anomaly,omitempty"`
	ChainStage string  `json:"chain_stage,omitempty"`
}
type Event struct {
	Timestamp string   `json:"timestamp"`
	Type      string   `json:"event_type"`
	SrcIP     string   `json:"src_ip"`
	SrcPort   int      `json:"src_port"`
	DestPort  int      `json:"dest_port"`
	Protocol  string   `json:"protocol"`
	Username  string   `json:"username,omitempty"`
	Password  string   `json:"password,omitempty"`
	CVE       []string `json:"cve"`
	Payload   string   `json:"payload"`
	ASA       ASA      `json:"asa"`
}

type Writer struct {
	mu   sync.Mutex
	path string
}

func New(path string) (*Writer, error) {
	f, e := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if e != nil {
		return nil, e
	}
	e = f.Close()
	return &Writer{path: path}, e
}
func Bound(s string, n int) string {
	s = strings.ToValidUTF8(s, "�")
	if len(s) > n {
		s = s[:n]
		s = strings.ToValidUTF8(s, "")
	}
	return s
}
func Printable(b []byte) string {
	s := Bound(string(b), 4096)
	return strings.Map(func(r rune) rune {
		if unicode.IsPrint(r) || r == '\n' || r == '\r' || r == '\t' {
			return r
		}
		return '.'
	}, s)
}
func (w *Writer) Write(e Event) error {
	e.Timestamp = time.Now().UTC().Format(time.RFC3339Nano)
	e.Username = Bound(e.Username, 512)
	e.Password = Bound(e.Password, 512)
	e.Payload = Bound(e.Payload, 4096)
	e.ASA.Profile.Version = Bound(e.ASA.Profile.Version, 64)
	e.ASA.Profile.Hostname = Bound(e.ASA.Profile.Hostname, 253)
	e.ASA.Group = Bound(e.ASA.Group, 256)
	e.ASA.Error = Bound(e.ASA.Error, 1024)
	if e.CVE == nil {
		e.CVE = []string{}
	}
	if h := e.ASA.HTTP; h != nil {
		h.URI = Bound(h.URI, 4096)
		h.UserAgent = Bound(h.UserAgent, 512)
	}
	if c := e.ASA.Client; c != nil {
		c.Version = Bound(c.Version, 128)
		c.Platform = Bound(c.Platform, 128)
		c.DeviceID = Bound(c.DeviceID, 256)
	}
	if k := e.ASA.IKE; k != nil {
		k.GroupName = Bound(k.GroupName, 256)
		if len(k.VendorIDs) > 32 {
			k.VendorIDs = k.VendorIDs[:32]
		}
		for i := range k.VendorIDs {
			k.VendorIDs[i] = Bound(k.VendorIDs[i], 128)
		}
		if len(k.Proposals) > 32 {
			k.Proposals = k.Proposals[:32]
		}
		for i := range k.Proposals {
			k.Proposals[i] = Bound(k.Proposals[i], 256)
		}
	}
	b, err := json.Marshal(e)
	if err != nil {
		return err
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	// Reopen for each event so logrotate rename/create needs no signal in scratch.
	f, err := os.OpenFile(w.path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = f.Write(append(b, '\n'))
	return err
}
func Peer(addr string) (string, int) {
	h, p, e := net.SplitHostPort(addr)
	if e != nil {
		return addr, 0
	}
	n, _ := strconv.Atoi(p)
	return h, n
}
func Report(w *Writer, e Event) {
	if err := w.Write(e); err != nil {
		fmt.Fprintf(os.Stderr, "eventlog: %v\n", err)
	}
}
