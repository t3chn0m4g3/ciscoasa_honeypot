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
	w := request(s, "POST", "/", "inert", "")
	if w.Code != 503 {
		t.Fatal(w.Code)
	}
	for i := 0; i < cap(s.workers); i++ {
		<-s.workers
	}
	if request(s, "GET", "/", "", "").Code != 200 {
		t.Fatal("worker permit leaked")
	}
}
