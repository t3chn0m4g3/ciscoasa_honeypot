package chain

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func TestStorageAndRestartQuota(t *testing.T) {
	dir := t.TempDir()
	s, e := New(dir)
	if e != nil {
		t.Fatal(e)
	}
	s.max = 10
	data := []byte("inert")
	u, e := s.Save(bytes.NewReader(data))
	if e != nil || !u.Stored || u.SHA256 != fmt.Sprintf("%x", sha256.Sum256(data)) {
		t.Fatal(u, e)
	}
	u, e = s.Save(bytes.NewReader(data))
	if e != nil || s.used != 5 {
		t.Fatal("duplicate quota", e)
	}
	var wg sync.WaitGroup
	for _, b := range []string{"second", "third!"} {
		wg.Add(1)
		go func(b string) {
			defer wg.Done()
			u, e := s.Save(bytes.NewBufferString(b))
			if e != nil || u.Stored {
				t.Error(u, e)
			}
		}(b)
	}
	wg.Wait()
	again, e := New(dir)
	if e != nil || again.used != 5 {
		t.Fatal(again, e)
	}
	u, e = s.Save(bytes.NewReader(make([]byte, FileLimit+1)))
	if e != nil || u.Stored || u.Size != FileLimit+1 {
		t.Fatal(u, e)
	}
	es, _ := os.ReadDir(dir)
	if len(es) != 1 {
		t.Fatal(es)
	}
	if _, e := os.Stat(filepath.Join(dir, u.SHA256)); !os.IsNotExist(e) {
		t.Fatal("oversized file stored")
	}
}
func TestSessionIsolationTTLAndBound(t *testing.T) {
	s, _ := New(t.TempDir())
	token, stage := s.State("", "192.0.2.1", true)
	if stage != "bypass" {
		t.Fatal(stage)
	}
	_, stage = s.State(token, "192.0.2.1", false)
	if stage != "upload" {
		t.Fatal(stage)
	}
	_, stage = s.State(token, "192.0.2.2", false)
	if stage != "observed" {
		t.Fatal(stage)
	}
	v := s.sessions[token]
	v.Last = time.Now().Add(-6 * time.Minute)
	s.sessions[token] = v
	_, stage = s.State(token, "192.0.2.1", false)
	if stage != "observed" {
		t.Fatal(stage)
	}
	for i := 0; i < 4100; i++ {
		s.State("", "192.0.2.1", true)
	}
	if len(s.sessions) > 4096 {
		t.Fatal(len(s.sessions))
	}
}

func TestOrphanTemporaryFilesAreRemoved(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, ".upload-orphan")
	os.WriteFile(file, []byte("inert"), 0600)
	if _, e := New(dir); e != nil {
		t.Fatal(e)
	}
	if _, e := os.Stat(file); !os.IsNotExist(e) {
		t.Fatal("orphan temporary upload retained")
	}
}
