package identity

import (
	"os"
	"path/filepath"
	"testing"
)

func TestPersistentIdentity(t *testing.T) {
	path := filepath.Join(t.TempDir(), "identity.json")
	p, e := Load(path)
	if e != nil {
		t.Fatal(e)
	}
	q, e := Load(path)
	if e != nil {
		t.Fatal(e)
	}
	if p.Certificate != q.Certificate || p.Hostname != q.Hostname {
		t.Fatal("identity changed")
	}
	info, _ := os.Stat(path)
	if info.Mode().Perm() != 0600 {
		t.Fatal(info.Mode())
	}
	os.WriteFile(path, []byte(`{"version":"broken"}`), 0600)
	if _, e := Load(path); e == nil {
		t.Fatal("invalid profile accepted")
	}
}
func TestFixBoundaries(t *testing.T) {
	for v, want := range map[string]bool{"9.16(4)84": true, "9.16(4)85": false, "9.18(4)66": true, "9.18(4)67": false, "9.20(4)5": true, "9.24(1)": false} {
		p := Profile{Version: v}
		if p.PreChainFix() != want {
			t.Error(v)
		}
	}
}
