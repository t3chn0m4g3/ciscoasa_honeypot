package webvpn

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"github.com/t3chn0m4g3/ciscoasa_honeypot/internal/chain"
	"github.com/t3chn0m4g3/ciscoasa_honeypot/internal/eventlog"
	"github.com/t3chn0m4g3/ciscoasa_honeypot/internal/identity"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func setup(t *testing.T) (*Server, string) {
	t.Helper()
	dir := t.TempDir()
	p, e := identity.Load(filepath.Join(dir, "identity.json"))
	if e != nil {
		t.Fatal(e)
	}
	p.Version = "9.20(4)5"
	lp := filepath.Join(dir, "log.json")
	l, _ := eventlog.New(lp)
	t.Cleanup(func() { l.Close() })
	s, _ := chain.New(filepath.Join(dir, "payloads"))
	return New(p, l, s), lp
}
func request(s *Server, method, path, body, ct string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, path, strings.NewReader(body))
	r.RemoteAddr = "192.0.2.1:12345"
	r.Header.Set("Content-Type", ct)
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	return w
}
func TestPortalAnyConnectCredentialsAndChain(t *testing.T) {
	s, lp := setup(t)
	w := request(s, "GET", "/+CSCOE+/logon.html", "", "")
	if !strings.Contains(w.Body.String(), "SSL VPN Service") || !strings.Contains(w.Body.String(), "/+CSCOU+/portal.css") {
		t.Fatal(w.Body.String())
	}
	w = request(s, "POST", "/", `<config-auth type="init"><version>4.10</version></config-auth>`, "application/xml")
	if !strings.Contains(w.Body.String(), s.Profile.Version) {
		t.Fatal(w.Body.String())
	}
	w = request(s, "POST", "/", `<config-auth type="auth-reply"><auth><username>test</username><password>secret</password></auth></config-auth>`, "application/xml")
	if !strings.Contains(w.Body.String(), `id="15"`) {
		t.Fatal(w.Body.String())
	}
	request(s, "POST", "/+webvpn+/index.html", "username=user&password=pass&group_list=Employees", "application/x-www-form-urlencoded")
	w = request(s, "POST", "/+CSCOU+//../+CSCOE+/files/file_action.html", "inert", "application/octet-stream")
	if w.Code != 200 || !strings.Contains(w.Body.String(), "CSRF token mismatch") {
		t.Fatal(w.Code)
	}
	b, _ := os.ReadFile(lp)
	var loggedUser, loggedUpload bool
	for _, line := range bytes.Split(bytes.TrimSpace(b), []byte("\n")) {
		var e eventlog.Event
		if err := json.Unmarshal(line, &e); err != nil {
			t.Fatal(err)
		}
		if e.Type == "webvpn.login" && e.Username == "user" && e.Password == "pass" {
			loggedUser = true
		}
		if e.Type == "upload" && e.ASA.Upload.Stored {
			loggedUpload = true
		}
	}
	if !loggedUser || !loggedUpload {
		t.Fatal(string(b))
	}
	s.Profile.Version = "9.20(4)10"
	w = request(s, "POST", "/+CSCOU+//../+CSCOE+/files/file_action.html", "inert", "")
	if w.Code != 403 {
		t.Fatal(w.Code)
	}
}
func TestMalformedAndBoundedBodies(t *testing.T) {
	s, _ := setup(t)
	for _, body := range []string{"<config-auth", "<host-scan-reply>"} {
		w := request(s, "POST", "/", body, "application/xml")
		if w.Code != 200 {
			t.Fatal(w.Code)
		}
	}
	w := request(s, "POST", "/", strings.Repeat("a", int(BodyLimit)+1), "")
	if w.Code != 413 {
		t.Fatal(w.Code)
	}
	w = request(s, "GET", "/+CSCOU+/../identity.json", "", "")
	if w.Code != 404 {
		t.Fatal(w.Code)
	}
}
func TestChunkedAndTLSStall(t *testing.T) {
	s, _ := setup(t)
	ts := httptest.NewUnstartedServer(s.Handler())
	ts.Config.ReadHeaderTimeout = time.Second
	ts.StartTLS()
	defer ts.Close()
	addr := ts.Listener.Addr().String()
	stalled, e := net.Dial("tcp", addr)
	if e != nil {
		t.Fatal(e)
	}
	defer stalled.Close()
	client := ts.Client()
	client.Timeout = 2 * time.Second
	req, _ := http.NewRequest("POST", ts.URL+"/+webvpn+/index.html", io.NopCloser(strings.NewReader("username=chunked&password=inert")))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	resp, e := client.Do(req)
	if e != nil {
		t.Fatal(e)
	}
	resp.Body.Close()
	if resp.StatusCode != 302 {
		t.Fatal(resp.StatusCode)
	}
}

func TestInvalidContentLengths(t *testing.T) {
	s, _ := setup(t)
	ts := httptest.NewUnstartedServer(s.Handler())
	ts.Config.ReadHeaderTimeout = time.Second
	ts.StartTLS()
	defer ts.Close()
	for _, length := range []string{"abc", "-1"} {
		c, e := (&net.Dialer{}).DialContext(context.Background(), "tcp", ts.Listener.Addr().String())
		if e != nil {
			t.Fatal(e)
		}
		conn := tls.Client(c, &tls.Config{InsecureSkipVerify: true})
		conn.SetDeadline(time.Now().Add(2 * time.Second))
		if e = conn.Handshake(); e != nil {
			t.Fatal(e)
		}
		fmt.Fprintf(conn, "POST / HTTP/1.1\r\nHost: test\r\nContent-Length: %s\r\nConnection: close\r\n\r\n", length)
		b, e := io.ReadAll(conn)
		conn.Close()
		if e != nil || !bytes.Contains(b, []byte("400 Bad Request")) {
			t.Fatal(string(b), e)
		}
	}
}

func TestConcurrentBodyBudget(t *testing.T) {
	s, _ := setup(t)
	for i := 0; i < cap(s.workers); i++ {
		s.workers <- struct{}{}
	}
	func() {
		defer func() {
			if recover() != http.ErrAbortHandler {
				t.Error("expected connection close")
			}
		}()
		request(s, "POST", "/", "inert", "")
	}()
	for i := 0; i < cap(s.workers); i++ {
		<-s.workers
	}
	if request(s, "GET", "/", "", "").Code != 200 {
		t.Fatal("worker permit retained")
	}
	if s.total != 0 || len(s.active) != 0 {
		t.Fatal("request permit retained")
	}
}

func TestUnauthenticatedAndPatchedUploadsRemainEvidence(t *testing.T) {
	s, lp := setup(t)
	for _, version := range []string{"9.20(4)5", "9.20(4)10"} {
		s.Profile.Version = version
		w := request(s, "POST", "/+CSCOE+/files/file_action.html", "inert upload", "application/octet-stream")
		if w.Code != 403 {
			t.Fatal(version, w.Code)
		}
	}
	b, _ := os.ReadFile(lp)
	for _, line := range bytes.Split(bytes.TrimSpace(b), []byte("\n")) {
		var e eventlog.Event
		json.Unmarshal(line, &e)
		if e.Type != "upload" || e.ASA.Upload == nil || !e.ASA.Upload.Stored {
			t.Fatal(string(line))
		}
	}
}

type waitingBody struct {
	Reader  *io.PipeReader
	Started chan struct{}
	once    sync.Once
}

func (b *waitingBody) Read(p []byte) (int, error) {
	b.once.Do(func() { close(b.Started) })
	return b.Reader.Read(p)
}
func (b *waitingBody) Close() error { return b.Reader.Close() }

func TestBodyReadBeforeWorker(t *testing.T) {
	s, _ := setup(t)
	var writes []*io.PipeWriter
	var wg sync.WaitGroup
	defer func() {
		for _, w := range writes {
			w.Close()
		}
		wg.Wait()
	}()
	for i := 0; i < 4; i++ {
		read, write := io.Pipe()
		writes = append(writes, write)
		body := &waitingBody{Reader: read, Started: make(chan struct{})}
		r := httptest.NewRequest("POST", "/", nil)
		r.Body = body
		r.RemoteAddr = "192.0.2.1:12345"
		wg.Add(1)
		go func() { defer wg.Done(); s.Handler().ServeHTTP(httptest.NewRecorder(), r) }()
		select {
		case <-body.Started:
		case <-time.After(time.Second):
			t.Fatal("body read not started")
		}
	}
	if len(s.workers) != 0 {
		t.Fatal("worker taken before body")
	}
	func() {
		defer func() {
			if recover() != http.ErrAbortHandler {
				t.Error("expected close at source limit")
			}
		}()
		request(s, "GET", "/", "", "")
	}()
	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = "198.51.100.1:12345"
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	if w.Code != 200 {
		t.Fatal(w.Code)
	}
	for _, w := range writes {
		w.Close()
	}
	wg.Wait()
	if s.total != 0 {
		t.Fatal("active requests retained")
	}
}

func TestRequestCapacity(t *testing.T) {
	s, _ := setup(t)
	for i := 0; i < 64; i++ {
		if !s.enter(fmt.Sprintf("192.0.2.%d", i)) {
			t.Fatal(i)
		}
	}
	if s.enter("198.51.100.1") {
		t.Fatal("global request count")
	}
	for i := 0; i < 64; i++ {
		s.leave(fmt.Sprintf("192.0.2.%d", i))
	}
	if !s.enter("198.51.100.1") {
		t.Fatal("request count not released")
	}
	s.leave("198.51.100.1")
}

func TestBodyReadDeadline(t *testing.T) {
	s, _ := setup(t)
	ts := httptest.NewUnstartedServer(s.Handler())
	ts.StartTLS()
	defer ts.Close()
	c, err := tls.Dial("tcp", ts.Listener.Addr().String(), &tls.Config{InsecureSkipVerify: true})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(7 * time.Second))
	fmt.Fprint(c, "POST / HTTP/1.1\r\nHost: test\r\nContent-Length: 10\r\n\r\na")
	buf := make([]byte, 1024)
	n, err := c.Read(buf)
	if n != 0 || err == nil {
		t.Fatal("expected closed body read", n, err)
	}
	if e, ok := err.(net.Error); ok && e.Timeout() {
		t.Fatal("body read deadline not applied")
	}
}

func TestHostscanRoutes(t *testing.T) {
	s, _ := setup(t)
	for _, path := range []string{"/", "/+CSCOE+/scan"} {
		w := request(s, "POST", path, "<host-scan-reply>", "application/xml")
		if w.Code != 200 || !strings.Contains(w.Body.String(), "config-auth") {
			t.Fatal(path, w.Code)
		}
	}
}

func TestTransportEventWindow(t *testing.T) {
	s, path := setup(t)
	w := transportLog{s: s, addr: ":8443"}
	for i := 0; i < 100; i++ {
		w.Write([]byte("http: TLS handshake error from 192.0.2.1:12345: input"))
	}
	b, _ := os.ReadFile(path)
	if len(bytes.Split(bytes.TrimSpace(b), []byte("\n"))) != 20 {
		t.Fatal("transport event count")
	}
	s.summaries.Tick(time.Now().Add(time.Minute))
	b, _ = os.ReadFile(path)
	var got eventlog.Event
	lines := bytes.Split(bytes.TrimSpace(b), []byte("\n"))
	json.Unmarshal(lines[len(lines)-1], &got)
	if got.Type != "http.ratelimit" || got.ASA.Count != 80 {
		t.Fatal(got)
	}
}

func TestConnectionCloseAtRequestCapacity(t *testing.T) {
	s, _ := setup(t)
	ts := httptest.NewUnstartedServer(s.Handler())
	ts.StartTLS()
	defer ts.Close()
	host, _, _ := net.SplitHostPort(ts.Listener.Addr().String())
	for i := 0; i < 4; i++ {
		if !s.enter(host) {
			t.Fatal(i)
		}
		defer s.leave(host)
	}
	c, err := tls.Dial("tcp", ts.Listener.Addr().String(), &tls.Config{InsecureSkipVerify: true})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(time.Second))
	fmt.Fprint(c, "POST / HTTP/1.1\r\nHost: test\r\nContent-Length: 100\r\n\r\na")
	buf := make([]byte, 1024)
	n, err := c.Read(buf)
	if n != 0 || err == nil {
		t.Fatal("expected connection close", n, err)
	}
	if e, ok := err.(net.Error); ok && e.Timeout() {
		t.Fatal("connection close waited for body")
	}
}

func TestBodyLimitSummary(t *testing.T) {
	s, path := setup(t)
	if request(s, "POST", "/", strings.Repeat("a", int(BodyLimit)+1), "").Code != 413 {
		t.Fatal("body size reply")
	}
	s.summaries.Tick(time.Now().Add(time.Minute))
	b, _ := os.ReadFile(path)
	var got eventlog.Event
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatal(err)
	}
	if got.Type != "http.ratelimit" || got.ASA.Count != 1 {
		t.Fatal(got.Type, got.ASA.Count)
	}
}
