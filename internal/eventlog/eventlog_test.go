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
