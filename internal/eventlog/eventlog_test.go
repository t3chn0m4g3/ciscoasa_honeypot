package eventlog

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestConcurrentJSONAndRotation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "events.json")
	w, e := New(path)
	if e != nil {
		t.Fatal(e)
	}
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if e := w.Write(Event{Type: "http.request", SrcIP: "192.0.2.1", Payload: "', src_ip: 'attacker'\n" + strings.Repeat("x", 10000)}); e != nil {
				t.Error(e)
			}
		}()
	}
	wg.Wait()
	b, _ := os.ReadFile(path)
	lines := strings.Split(strings.TrimSpace(string(b)), "\n")
	if len(lines) != 50 {
		t.Fatal(len(lines))
	}
	for _, line := range lines {
		var e Event
		if err := json.Unmarshal([]byte(line), &e); err != nil {
			t.Fatal(err)
		}
		if e.SrcIP != "192.0.2.1" || len(e.Payload) > 4096 {
			t.Fatal(e)
		}
		if _, err := time.Parse(time.RFC3339Nano, e.Timestamp); err != nil || !strings.HasSuffix(e.Timestamp, "Z") {
			t.Fatal(e.Timestamp)
		}
	}
	os.Rename(path, path+".1")
	if err := w.Write(Event{Type: "error"}); err != nil {
		t.Fatal(err)
	}
	if _, e := os.Stat(path); e != nil {
		t.Fatal(e)
	}
}

func TestLoggedStringsEscapeControlCharacters(t *testing.T) {
	path := filepath.Join(t.TempDir(), "events.json")
	w, e := New(path)
	if e != nil {
		t.Fatal(e)
	}
	value := "user\x1b[2J\r\nnext\x00"
	ev := Event{Type: "webvpn.login", Username: value, Password: value, ASA: ASA{Group: value, Error: value, HTTP: &HTTP{URI: value, UserAgent: value}, Client: &Client{Version: value, Platform: value, DeviceID: value}, IKE: &IKE{GroupName: value}}}
	if e := w.Write(ev); e != nil {
		t.Fatal(e)
	}
	b, _ := os.ReadFile(path)
	var got Event
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatal(err)
	}
	want := `user\x1b[2J\x0d\x0anext\x00`
	for _, s := range []string{got.Username, got.Password, got.ASA.Group, got.ASA.Error, got.ASA.HTTP.URI, got.ASA.HTTP.UserAgent, got.ASA.Client.Version, got.ASA.Client.Platform, got.ASA.Client.DeviceID, got.ASA.IKE.GroupName} {
		if s != want {
			t.Fatalf("%q", s)
		}
	}
}

func TestMarkupStaysCompact(t *testing.T) {
	path := filepath.Join(t.TempDir(), "events.json")
	w, _ := New(path)
	w.Write(Event{Type: "http.request", Payload: strings.Repeat("<", 4096)})
	b, _ := os.ReadFile(path)
	if len(b) > 4096+512 {
		t.Fatal(len(b))
	}
}

func TestFileSizeAndRotation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "events.json")
	w, err := New(path)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	if err := os.Truncate(path, FileLimit-8); err != nil {
		t.Fatal(err)
	}
	if err := w.Write(Event{Type: "http.request"}); err != nil {
		t.Fatal(err)
	}
	info, _ := os.Stat(path)
	if info.Size() != FileLimit-8 {
		t.Fatal(info.Size())
	}
	w.Close()
	w, err = New(path)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	if err := w.Write(Event{Type: "http.request"}); err != nil {
		t.Fatal(err)
	}
	info, _ = os.Stat(path)
	if info.Size() != FileLimit-8 {
		t.Fatal(info.Size())
	}
	if err := os.Truncate(path, 0); err != nil {
		t.Fatal(err)
	}
	if err := w.Write(Event{Type: "http.request"}); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(path)
	if !json.Valid(b) {
		t.Fatal("missing line after truncation")
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := w.Write(Event{Type: "http.request"}); err != nil {
		t.Fatal(err)
	}
	b, _ = os.ReadFile(path)
	if !json.Valid(b) {
		t.Fatal("missing line after replacement")
	}
}

func TestResultingStringLength(t *testing.T) {
	if got := Clean(strings.Repeat("\x00", 512), 512); len(got) > 512 || strings.ContainsRune(got, 0) {
		t.Fatal(len(got))
	}
}

func TestSharedEventValues(t *testing.T) {
	w, err := New(filepath.Join(t.TempDir(), "events.json"))
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	e := Event{ASA: ASA{HTTP: &HTTP{URI: "/a\x1b"}, IKE: &IKE{VendorIDs: []string{"value\x00"}}}}
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := w.Write(e); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	if e.ASA.HTTP.URI != "/a\x1b" || e.ASA.IKE.VendorIDs[0] != "value\x00" {
		t.Fatal("caller values changed")
	}
}
