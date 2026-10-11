package chain

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"io"
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

func TestFileCountAndDuplicates(t *testing.T) {
	s, err := New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	s.maxFiles = 2
	for _, value := range []string{"", "one"} {
		u, err := s.Save(bytes.NewBufferString(value))
		if err != nil || !u.Stored {
			t.Fatal(u, err)
		}
	}
	for _, value := range []string{"", "one", "two"} {
		u, err := s.Save(bytes.NewBufferString(value))
		if err != nil || u.Stored != (value != "two") {
			t.Fatal(u, err)
		}
	}
	if s.files != 2 || s.charged != storageCost(0)+storageCost(3) {
		t.Fatal(s.files, s.charged)
	}
	entries, _ := os.ReadDir(s.dir)
	if len(entries) != 2 {
		t.Fatal(len(entries))
	}
}

func TestCalculatedBudgetAndRestart(t *testing.T) {
	dir := t.TempDir()
	s, err := New(dir)
	if err != nil {
		t.Fatal(err)
	}
	s.maxStorage = storageCost(1)
	u, err := s.Save(bytes.NewBufferString("a"))
	if err != nil || !u.Stored {
		t.Fatal(u, err)
	}
	u, err = s.Save(bytes.NewBufferString("b"))
	if err != nil || u.Stored {
		t.Fatal(u, err)
	}
	if err := os.WriteFile(filepath.Join(dir, "existing"), []byte("manual"), 0600); err != nil {
		t.Fatal(err)
	}
	again, err := New(dir)
	if err != nil || again.files != 2 || again.used != 7 || again.charged != storageCost(1)+storageCost(6) {
		t.Fatal(again, err)
	}
	again.maxFiles = 1
	again.maxStorage = storageCost(1)
	for _, value := range []string{"a", "new"} {
		u, err := again.Save(bytes.NewBufferString(value))
		if err != nil || u.Stored != (value == "a") {
			t.Fatal(u, err)
		}
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 2 {
		t.Fatal(len(entries))
	}
}

func TestStorageCostBoundaries(t *testing.T) {
	for _, tc := range []struct{ size, want int64 }{{0, 16384}, {1, 32768}, {16384, 32768}, {16385, 49152}, {FileLimit, FileLimit + 16384}} {
		if got := storageCost(tc.size); got != tc.want {
			t.Fatal(tc, got)
		}
	}
}

func TestParallelFileBudget(t *testing.T) {
	s, err := New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	s.maxFiles = 5
	var wg sync.WaitGroup
	for i := 0; i < 40; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			if _, err := s.Save(bytes.NewBufferString(fmt.Sprint(i))); err != nil {
				t.Error(err)
			}
		}(i)
	}
	wg.Wait()
	entries, _ := os.ReadDir(s.dir)
	if len(entries) != 5 || s.files != 5 || s.charged != 5*storageCost(1) {
		t.Fatal(len(entries), s.files, s.charged)
	}
}

func TestReadAndFileErrorsKeepCounts(t *testing.T) {
	s, err := New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Save(errorReader{}); err == nil {
		t.Fatal("expected read error")
	}
	if err := os.Remove(s.dir); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Save(bytes.NewBufferString("inert")); err == nil {
		t.Fatal("expected file error")
	}
	if s.files != 0 || s.used != 0 || s.charged != 0 {
		t.Fatal(s.files, s.used, s.charged)
	}
}

type errorReader struct{}

func (errorReader) Read([]byte) (int, error) { return 0, fmt.Errorf("read unavailable") }

func TestDirectoryBatchesAndLinks(t *testing.T) {
	dir := t.TempDir()
	for i := 0; i < 260; i++ {
		if err := os.WriteFile(filepath.Join(dir, fmt.Sprint(i)), []byte("x"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	target := filepath.Join(t.TempDir(), "outside")
	if err := os.WriteFile(target, []byte("outside"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(dir, "link")); err != nil {
		t.Fatal(err)
	}
	s, err := New(dir)
	if err != nil || s.files != 260 || s.used != 260 || s.charged != 260*storageCost(1) {
		t.Fatal(s, err)
	}
	data, err := os.ReadFile(target)
	if err != nil || string(data) != "outside" {
		t.Fatal(string(data), err)
	}
}

func TestExistingDestinationAndPartialRead(t *testing.T) {
	s, err := New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	value := []byte("inert")
	sum := fmt.Sprintf("%x", sha256.Sum256(value))
	if err := os.Mkdir(filepath.Join(s.dir, sum), 0700); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Save(bytes.NewReader(value)); err == nil {
		t.Fatal("expected destination error")
	}
	if _, err := s.Save(io.MultiReader(bytes.NewReader(value), errorReader{})); err == nil {
		t.Fatal("expected partial read error")
	}
	entries, _ := os.ReadDir(s.dir)
	if len(entries) != 1 || s.files != 0 || s.used != 0 || s.charged != 0 {
		t.Fatal(len(entries), s.files, s.used, s.charged)
	}
}
