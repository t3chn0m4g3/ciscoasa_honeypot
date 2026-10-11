// Package chain stores inert uploads and models only externally visible state.
package chain

import (
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

type session struct {
	IP    string
	Stage string
	Last  time.Time
}
type Store struct {
	mu       sync.Mutex
	dir      string
	used     int64
	max      int64
	sessions map[string]session
}

func New(dir string) (*Store, error) {
	if e := os.MkdirAll(dir, 0700); e != nil {
		return nil, e
	}
	s := &Store{dir: dir, max: TotalLimit, sessions: map[string]session{}}
	es, e := os.ReadDir(dir)
	if e != nil {
		return nil, e
	}
	for _, x := range es {
		if x.Type().IsRegular() && strings.HasPrefix(x.Name(), ".upload-") {
			if e := os.Remove(filepath.Join(dir, x.Name())); e != nil {
				return nil, e
			}
			continue
		}
		if x.Type().IsRegular() && len(x.Name()) == 64 {
			b, e := hex.DecodeString(x.Name())
			if e == nil && len(b) == 32 {
				i, e := x.Info()
				if e != nil {
					return nil, e
				}
				s.used += i.Size()
			}
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
	available := s.max - s.used
	if available < 0 {
		available = 0
	}
	if available > FileLimit {
		available = FileLimit
	}
	h := sha256.New()
	f, e := os.CreateTemp(s.dir, ".upload-")
	if e != nil {
		return nil, e
	}
	defer os.Remove(f.Name())
	// Keep both temporary and committed bytes inside the disk quota; hash the remainder.
	n, e := io.Copy(io.MultiWriter(h, f), io.LimitReader(r, available))
	if e != nil {
		f.Close()
		return nil, e
	}
	extra, e := io.Copy(h, r)
	if e != nil {
		f.Close()
		return nil, e
	}
	n += extra
	if e = f.Sync(); e != nil {
		f.Close()
		return nil, e
	}
	if e = f.Close(); e != nil {
		return nil, e
	}
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
	if n > available || s.used+n > s.max {
		return u, nil
	}
	if e = os.Rename(f.Name(), path); e != nil {
		return nil, e
	}
	s.used += n
	u.Stored = true
	u.File = sum
	return u, nil
}
func UploadPath(raw string) bool {
	u := strings.ToLower(raw)
	return strings.Contains(u, "cscoefilesfileaction.html") || strings.Contains(u, "/files/file_action.html")
}
