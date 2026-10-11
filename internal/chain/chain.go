// Package chain stores inert uploads and models only externally visible state.
package chain

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"github.com/t3chn0m4g3/ciscoasa_honeypot/internal/eventlog"
	"github.com/t3chn0m4g3/ciscoasa_honeypot/internal/identity"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

const FileLimit int64 = 2 << 20
const TotalLimit int64 = 256 << 20
const StoredFileLimit = 4096
const StorageUnit int64 = 16 << 10

func storageCost(size int64) int64 {
	return ((size+StorageUnit-1)/StorageUnit + 1) * StorageUnit
}

type session struct {
	IP    string
	Stage string
	Last  time.Time
}
type Store struct {
	mu         sync.Mutex
	dir        string
	used       int64
	max        int64
	charged    int64
	maxStorage int64
	files      int
	maxFiles   int
	sessions   map[string]session
}

func New(dir string) (*Store, error) {
	if e := os.MkdirAll(dir, 0700); e != nil {
		return nil, e
	}

	s := &Store{dir: dir, max: TotalLimit, maxStorage: TotalLimit, maxFiles: StoredFileLimit, sessions: map[string]session{}}
	directory, err := os.Open(dir)
	if err != nil {
		return nil, err
	}
	defer directory.Close()
	for {
		entries, err := directory.ReadDir(128)
		if err != nil && !errors.Is(err, io.EOF) {
			return nil, err
		}
		for _, entry := range entries {
			if !entry.Type().IsRegular() {
				continue
			}
			info, err := entry.Info()
			if err != nil {
				return nil, err
			}
			if !info.Mode().IsRegular() {
				continue
			}
			if strings.HasPrefix(entry.Name(), ".upload-") {
				if err := os.Remove(filepath.Join(dir, entry.Name())); err != nil {
					return nil, err
				}
				continue
			}
			s.files++
			s.used += info.Size()
			s.charged += storageCost(info.Size())
		}
		if errors.Is(err, io.EOF) {
			break
		}
	}
	return s, nil
}

func (s *Store) State(token, ip string, bypass bool) (string, string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	for k, v := range s.sessions {
		if now.Sub(v.Last) > 5*time.Minute {
			delete(s.sessions, k)
		}
	}
	v, ok := s.sessions[token]
	if !ok || v.IP != ip {
		if !bypass {
			return "", "observed"
		}
		if len(s.sessions) >= 4096 {
			var oldest string
			var when time.Time
			for k, x := range s.sessions {
				if oldest == "" || x.Last.Before(when) {
					oldest = k
					when = x.Last
				}
			}
			delete(s.sessions, oldest)
		}
		token = identity.Token(16)
		v = session{IP: ip}
	}
	if bypass {
		v.Stage = "bypass"
	} else if v.Stage == "bypass" || v.Stage == "upload" {
		v.Stage = "upload"
	}
	v.Last = now
	s.sessions[token] = v
	return token, v.Stage
}
func (s *Store) Save(r io.Reader) (*eventlog.Upload, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	h := sha256.New()
	var content bytes.Buffer
	n, err := io.Copy(io.MultiWriter(h, &content), io.LimitReader(r, FileLimit))
	if err != nil {
		return nil, err
	}
	extra, err := io.Copy(h, r)
	if err != nil {
		return nil, err
	}
	n += extra
	sum := hex.EncodeToString(h.Sum(nil))
	u := &eventlog.Upload{SHA256: sum, Size: n}
	if n > FileLimit {
		return u, nil
	}
	path := filepath.Join(s.dir, sum)
	if info, e := os.Lstat(path); e == nil {
		if !info.Mode().IsRegular() {
			return nil, errors.New("payload destination is not a regular file")
		}
		u.Stored = true
		u.File = sum
		return u, nil
	} else if !errors.Is(e, os.ErrNotExist) {
		return nil, e
	}

	cost := storageCost(n)
	if s.files >= s.maxFiles || n > s.max-s.used || cost > s.maxStorage-s.charged {
		return u, nil
	}
	f, err := os.CreateTemp(s.dir, ".upload-")
	if err != nil {
		return nil, err
	}
	defer func() { f.Close(); os.Remove(f.Name()) }()
	if _, err := io.Copy(f, &content); err != nil {
		return nil, err
	}
	if err := f.Sync(); err != nil {
		return nil, err
	}
	if err := f.Close(); err != nil {
		return nil, err
	}
	if err := os.Rename(f.Name(), path); err != nil {
		return nil, err
	}
	s.used += n
	s.charged += cost
	s.files++
	u.Stored = true
	u.File = sum
	return u, nil
}
func UploadPath(raw string) bool {
	u := strings.ToLower(raw)
	return strings.Contains(u, "cscoefilesfileaction.html") || strings.Contains(u, "/files/file_action.html")
}
