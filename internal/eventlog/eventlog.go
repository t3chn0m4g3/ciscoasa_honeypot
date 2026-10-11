// Package eventlog writes bounded JSON lines without interpreting attacker text.
package eventlog

import (
	"bytes"
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
	Count      int     `json:"count,omitempty"`
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

const FileLimit int64 = 64 << 20

type Writer struct {
	mu     sync.Mutex
	path   string
	file   *os.File
	info   os.FileInfo
	closed bool
}

func New(path string) (*Writer, error) {
	w := &Writer{path: path}
	if e := w.open(); e != nil {
		return nil, e
	}
	return w, nil
}

// open (re)opens the log in append mode and remembers which file it is.
func (w *Writer) open() error {
	if w.file != nil {
		w.file.Close()
		w.file = nil
	}
	f, e := os.OpenFile(w.path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if e != nil {
		return e
	}
	info, e := f.Stat()
	if e != nil {
		f.Close()
		return e
	}
	w.file, w.info = f, info
	return nil
}
func Bound(s string, n int) string {
	s = strings.ToValidUTF8(s, "�")
	if len(s) > n {
		s = s[:n]
		s = strings.ToValidUTF8(s, "")
	}
	return s
}

// Clean bounds a single-line string and writes control and other
// non-printable characters as \xNN or \uNNNN.
func Clean(s string, n int) string {
	s = Bound(s, n)
	var b strings.Builder
	for _, r := range s {
		switch {
		case unicode.IsPrint(r):
			b.WriteRune(r)
		case r < 0x100:
			fmt.Fprintf(&b, "\\x%02x", r)
		default:
			fmt.Fprintf(&b, "\\u%04x", r)
		}
	}
	return Bound(b.String(), n)
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
	if e.ASA.HTTP != nil {
		v := *e.ASA.HTTP
		e.ASA.HTTP = &v
	}
	if e.ASA.Client != nil {
		v := *e.ASA.Client
		e.ASA.Client = &v
	}
	if e.ASA.IKE != nil {
		v := *e.ASA.IKE
		v.VendorIDs = append([]string(nil), v.VendorIDs...)
		v.Proposals = append([]string(nil), v.Proposals...)
		e.ASA.IKE = &v
	}
	e.Type = Clean(e.Type, 64)
	e.SrcIP = Clean(e.SrcIP, 64)
	e.Protocol = Clean(e.Protocol, 16)
	e.ASA.Anomaly = Clean(e.ASA.Anomaly, 1024)
	e.ASA.ChainStage = Clean(e.ASA.ChainStage, 64)
	e.Timestamp = time.Now().UTC().Format(time.RFC3339Nano)
	e.Username = Clean(e.Username, 512)
	e.Password = Clean(e.Password, 512)
	e.Payload = Bound(e.Payload, 4096)
	e.ASA.Profile.Version = Clean(e.ASA.Profile.Version, 64)
	e.ASA.Profile.Hostname = Clean(e.ASA.Profile.Hostname, 253)
	e.ASA.Group = Clean(e.ASA.Group, 256)
	e.ASA.Error = Clean(e.ASA.Error, 1024)
	e.CVE = append([]string(nil), e.CVE...)
	if len(e.CVE) > 32 {
		e.CVE = e.CVE[:32]
	}
	for i := range e.CVE {
		e.CVE[i] = Clean(e.CVE[i], 64)
	}
	if e.CVE == nil {
		e.CVE = []string{}
	}
	if h := e.ASA.HTTP; h != nil {
		h.Method = Clean(h.Method, 32)
		h.URI = Clean(h.URI, 4096)
		h.UserAgent = Clean(h.UserAgent, 512)
	}
	if c := e.ASA.Client; c != nil {
		c.Version = Clean(c.Version, 128)
		c.Platform = Clean(c.Platform, 128)
		c.DeviceID = Clean(c.DeviceID, 256)
	}
	if k := e.ASA.IKE; k != nil {
		k.GroupName = Clean(k.GroupName, 256)
		if len(k.VendorIDs) > 32 {
			k.VendorIDs = k.VendorIDs[:32]
		}
		for i := range k.VendorIDs {
			k.VendorIDs[i] = Clean(k.VendorIDs[i], 128)
		}
		if len(k.Proposals) > 32 {
			k.Proposals = k.Proposals[:32]
		}
		for i := range k.Proposals {
			k.Proposals[i] = Clean(k.Proposals[i], 256)
		}
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(e); err != nil {
		return err
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed {
		return os.ErrClosed
	}
	// A renamed or removed log is reopened; copytruncate keeps the same file.
	if info, err := os.Stat(w.path); w.file == nil || err != nil || !os.SameFile(info, w.info) {
		if err := w.open(); err != nil {
			return err
		}
	}
	info, err := w.file.Stat()
	if err != nil {
		return err
	}
	if info.Size()+int64(buf.Len()) > FileLimit {
		return nil
	}
	if n, err := w.file.Write(buf.Bytes()); err != nil {
		if n != 0 {
			return err
		}
		if err := w.open(); err != nil {
			return err
		}
		info, statErr := w.file.Stat()
		if statErr != nil {
			return statErr
		}
		if info.Size()+int64(buf.Len()) > FileLimit {
			return nil
		}
		_, err = w.file.Write(buf.Bytes())
		return err
	}
	return nil
}
func (w *Writer) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.closed = true
	if w.file == nil {
		return nil
	}
	err := w.file.Close()
	w.file = nil
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
