package webvpn

import (
	"bytes"
	"crypto/tls"
	"embed"
	"encoding/xml"
	"fmt"
	"github.com/t3chn0m4g3/ciscoasa_honeypot/internal/anyconnect"
	"github.com/t3chn0m4g3/ciscoasa_honeypot/internal/asdm"
	"github.com/t3chn0m4g3/ciscoasa_honeypot/internal/chain"
	"github.com/t3chn0m4g3/ciscoasa_honeypot/internal/eventlog"
	"github.com/t3chn0m4g3/ciscoasa_honeypot/internal/identity"
	"github.com/t3chn0m4g3/ciscoasa_honeypot/internal/rules"
	"io"
	"log"
	"mime"
	"mime/multipart"
	"net/http"
	"net/url"
	"path"
	"strings"
	"sync"
	"time"
)

//go:embed assets/*
var assets embed.FS

const BodyLimit int64 = 4 << 20

type attempts struct {
	Count int
	Last  time.Time
}
type Server struct {
	Profile *identity.Profile
	Log     *eventlog.Writer
	Store   *chain.Store
	mu      sync.Mutex
	sprays  map[string]attempts
	workers chan struct{}
}

func New(p *identity.Profile, l *eventlog.Writer, s *chain.Store) *Server {
	return &Server{Profile: p, Log: l, Store: s, sprays: map[string]attempts{}, workers: make(chan struct{}, 32)}
}
func (s *Server) Handler() http.Handler { return http.HandlerFunc(s.serve) }
func (s *Server) HTTPServer(addr string) *http.Server {
	return &http.Server{Addr: addr, Handler: s.Handler(), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second, WriteTimeout: 15 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 32 << 10, ErrorLog: log.New(transportLog{s: s, addr: addr}, "", 0), TLSNextProto: map[string]func(*http.Server, *tls.Conn, http.Handler){}}
}
func (s *Server) spray(ip string, e *eventlog.Event) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	for k, v := range s.sprays {
		if now.Sub(v.Last) > time.Minute {
			delete(s.sprays, k)
		}
	}
	v := s.sprays[ip]
	if now.Sub(v.Last) > time.Minute {
		v.Count = 0
	}
	v.Count++
	v.Last = now
	if len(s.sprays) < 4096 || s.sprays[ip].Count > 0 {
		s.sprays[ip] = v
	}
	if v.Count >= 10 {
		e.CVE = append(e.CVE, "CVE-2023-20269", "CVE-2024-20481")
		e.ASA.Anomaly = "password-spraying heuristic"
	}
}
func headers(w http.ResponseWriter) {
	w.Header().Set("X-Transcend-Version", "1")
	w.Header().Set("X-Frame-Options", "SAMEORIGIN")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
}
func cookie(w http.ResponseWriter, name, value string) {
	http.SetCookie(w, &http.Cookie{Name: name, Value: value, Path: "/", Secure: true, HttpOnly: name != "webvpnlogin" && name != "webvpnlang", SameSite: http.SameSiteLaxMode})
}
func (s *Server) serve(w http.ResponseWriter, r *http.Request) {
	ip, port := eventlog.Peer(r.RemoteAddr)
	dest := 8443
	if a, ok := r.Context().Value(http.LocalAddrContextKey).(interface{ String() string }); ok {
		_, dest = eventlog.Peer(a.String())
	}
	e := eventlog.Event{Type: "http.request", SrcIP: ip, SrcPort: port, DestPort: dest, Protocol: "tcp", ASA: eventlog.ASA{Profile: eventlog.Profile{Version: s.Profile.Version, Hostname: s.Profile.Hostname}, HTTP: &eventlog.HTTP{Method: r.Method, URI: r.RequestURI, UserAgent: r.UserAgent()}}}
	defer func() {
		if x := recover(); x != nil {
			e.Type = "error"
			e.ASA.Error = fmt.Sprintf("handler panic: %v", x)
			http.Error(w, "Internal Server Error", 500)
		}
		eventlog.Report(s.Log, e)
	}()
	select {
	case s.workers <- struct{}{}:
		defer func() { <-s.workers }()
	default:
		e.Type = "error"
		e.ASA.Error = "request concurrency limit"
		http.Error(w, "Service Unavailable", 503)
		return
	}
	headers(w)
	r.Body = http.MaxBytesReader(w, r.Body, BodyLimit)
	b, err := io.ReadAll(r.Body)
	if err != nil {
		e.Type = "error"
		e.ASA.Error = err.Error()
		http.Error(w, "Request Entity Too Large", 413)
		return
	}
	e.Payload = eventlog.Printable(b)
	if len(b) == 0 {
		e.Payload = eventlog.Bound(r.Method+" "+r.RequestURI, 4096)
	}
	e.CVE = rules.Match(r.Method, r.RequestURI, r.Header.Get("Content-Type"), b)
	if len(e.CVE) > 0 {
		e.Type = "exploit"
	}
	raw := rules.Decode(r.RequestURI)
	p := r.URL.Path
	if strings.Contains(strings.ToLower(p), "/+cscoe+/") && strings.Contains(strings.ToLower(string(b)), "host-scan-reply") {
		e.Type = "anyconnect.hostscan"
		var parsed any
		if err := xml.Unmarshal(b, &parsed); err != nil {
			e.ASA.Anomaly = "malformed host-scan-reply heuristic"
		}
		w.Header().Set("Content-Type", "application/xml; charset=utf-8")
		w.Write([]byte(anyconnect.Failure(s.Profile, true)))
		return
	}
	bypass := rules.Has(e.CVE, "CVE-2025-20362")
	if bypass || chain.UploadPath(raw) {
		s.handleChain(w, r, b, &e, bypass)
		return
	}
	if asdm.Path(p) {
		asdm.Handle(w, r, &e)
		return
	}
	if strings.Contains(string(b), "host-scan-reply") {
		e.Type = "anyconnect.hostscan"
		var parsed any
		if err := xml.Unmarshal(b, &parsed); err != nil {
			e.ASA.Anomaly = "malformed host-scan-reply heuristic"
		}
		w.Header().Set("Content-Type", "application/xml; charset=utf-8")
		w.Write([]byte(anyconnect.Failure(s.Profile, true)))
		return
	}
	if r.Header.Get("X-Aggregate-Auth") == "1" || strings.Contains(string(b), "config-auth") {
		w.Header().Set("Content-Type", "application/xml; charset=utf-8")
		if r.Method == "GET" || r.Method == "HEAD" {
			e.Type = "anyconnect.init"
			w.Write([]byte(anyconnect.Init(s.Profile, "")))
			return
		}
		req, er := anyconnect.Parse(b)
		if er != nil {
			e.Type = "error"
			e.ASA.Error = "invalid AnyConnect XML"
			e.ASA.Anomaly = "malformed WebVPN request; CVE-2026-20349 relevance unconfirmed"
			w.Write([]byte(anyconnect.Failure(s.Profile, true)))
			return
		}
		e.ASA.Client = anyconnect.Metadata(req)
		e.ASA.Group = req.Group
		switch req.Type {
		case "init":
			e.Type = "anyconnect.init"
			w.Write([]byte(anyconnect.Init(s.Profile, req.Group)))
		case "auth-reply":
			e.Type = "anyconnect.auth"
			e.Username = req.Auth.Username
			e.Password = req.Auth.Password
			s.spray(ip, &e)
			w.Write([]byte(anyconnect.Failure(s.Profile, false)))
		default:
			e.Type = "error"
			e.ASA.Error = "unsupported AnyConnect request"
			w.Write([]byte(anyconnect.Failure(s.Profile, true)))
		}
		return
	}
	if r.Method == "POST" && (p == "/" || p == "/+webvpn+/index.html" || p == "/+CSCOE+/logon.html") {
		form, _ := url.ParseQuery(string(b))
		e.Type = "webvpn.login"
		e.Username = form.Get("username")
		e.Password = form.Get("password")
		e.ASA.Group = form.Get("group_list")
		if e.ASA.Group == "" {
			e.ASA.Group = form.Get("tgroup")
		}
		s.spray(ip, &e)
		cookie(w, "webvpnlogin", "1")
		w.Header().Set("Location", "/+CSCOE+/logon.html?reason=1")
		w.WriteHeader(302)
		return
	}
	if r.Method != "GET" && r.Method != "HEAD" {
		w.WriteHeader(403)
		w.Write([]byte("Forbidden"))
		return
	}
	if p == "/" {
		for _, c := range []string{"webvpn", "webvpnc"} {
			cookie(w, c, "")
		}
		cookie(w, "webvpnlogin", "1")
		cookie(w, "webvpnlang", "en")
		w.Write([]byte(`<html><head><title>SSL VPN Service</title></head><body><script>document.location="/+CSCOE+/logon.html";</script></body></html>`))
		return
	}
	if p == "/CACHE/sdesktop/data.xml" {
		w.Header().Set("Content-Type", "application/xml; charset=utf-8")
		w.Write([]byte(`<?xml version="1.0"?><config><hostscan><version>4.10.08029</version></hostscan></config>`))
		return
	}
	if p == "/+CSCOE+/logon.html" {
		s.logon(w, r.URL.Query().Get("reason") == "1")
		return
	}
	// Explicit asset prefixes prevent arbitrary basename matches and traversal.
	if (strings.HasPrefix(p, "/+CSCOU+/") || strings.HasPrefix(p, "/+CSCOE+/")) && !strings.Contains(raw, "..") {
		name := strings.TrimPrefix(p, "/+CSCOU+/")
		name = strings.TrimPrefix(name, "/+CSCOE+/")
		if !strings.Contains(name, "/") && name != "index.html" && name != "logon_failure" && name != "logon_redir.html" {
			if data, er := assets.ReadFile("assets/" + name); er == nil {
				ct := mime.TypeByExtension(path.Ext(name))
				if ct == "" {
					ct = "application/octet-stream"
				}
				w.Header().Set("Content-Type", ct)
				w.Write(data)
				return
			}
		}
	}
	w.WriteHeader(404)
	data, _ := assets.ReadFile("assets/wrong_url.html")
	w.Write(data)
}
func (s *Server) logon(w http.ResponseWriter, failed bool) {
	data, _ := assets.ReadFile("assets/logon.html")
	html := strings.ReplaceAll(string(data), "/+CSCOE+/portal.css", "/+CSCOU+/portal.css")
	html = strings.ReplaceAll(html, "<title></title>", "<title>SSL VPN Service</title>")
	start := strings.Index(html, `<select`)
	if start >= 0 {
		end := strings.Index(html[start:], `</select>`)
		if end >= 0 {
			tagEnd := strings.Index(html[start:], ">")
			if tagEnd >= 0 {
				var opts strings.Builder
				for _, g := range s.Profile.Groups {
					fmt.Fprintf(&opts, `<option value="%s">%s</option>`, anyconnect.Escape(g.Name), anyconnect.Escape(g.Alias))
				}
				html = html[:start+tagEnd+1] + opts.String() + html[start+end:]
			}
		}
	}
	if failed {
		html = strings.Replace(html, "<body", `<body`, 1)
		html = strings.Replace(html, "</form>", `<p>Login failed.</p></form>`, 1)
	}
	cookie(w, "webvpnlogin", "1")
	w.Write([]byte(html))
}
func (s *Server) handleChain(w http.ResponseWriter, r *http.Request, b []byte, e *eventlog.Event, bypass bool) {
	if !s.Profile.PreChainFix() {
		w.WriteHeader(403)
		w.Write([]byte("Forbidden"))
		return
	}
	token := ""
	if c, err := r.Cookie("webvpn"); err == nil {
		token = c.Value
	}
	token, stage := s.Store.State(token, e.SrcIP, bypass)
	e.ASA.ChainStage = stage
	if token != "" {
		cookie(w, "webvpn", token)
	}
	if r.Method == "POST" && chain.UploadPath(rules.Decode(r.RequestURI)) {
		ct, params, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
		saved := false
		if err == nil && ct == "multipart/form-data" && len(params["boundary"]) <= 70 {
			mr := multipart.NewReader(bytes.NewReader(b), params["boundary"])
			for n := 0; n < 16; n++ {
				part, er := mr.NextPart()
				if er != nil {
					break
				}
				if part.FileName() != "" {
					u, er := s.Store.Save(part)
					part.Close()
					if er != nil {
						e.Type = "error"
						e.ASA.Error = er.Error()
					} else {
						e.Type = "upload"
						e.ASA.Upload = u
						saved = true
					}
					break
				}
				part.Close()
			}
		}
		// Oversized or malformed multipart boundaries: preserve the bounded body as inert evidence.
		if !saved && len(b) > 0 {
			u, er := s.Store.Save(bytes.NewReader(b))
			if er != nil {
				e.Type = "error"
				e.ASA.Error = er.Error()
			} else {
				e.Type = "upload"
				e.ASA.Upload = u
			}
		}
	}
	w.WriteHeader(200)
	w.Write([]byte(`<script>alert('CSRF token mismatch');</script>Failed to upload file`))
}
