package rules

import (
	_ "embed"
	"encoding/json"
	"mime"
	"net/url"
	"strings"
)

//go:embed rules.json
var table []byte

type Rule struct {
	CVE        string   `json:"cve"`
	Method     string   `json:"method"`
	Path       []string `json:"path"`
	URI        []string `json:"uri"`
	Body       []string `json:"body"`
	BoundaryGT int      `json:"boundary_gt"`
}

var all = []Rule{}

func init() {
	if e := json.Unmarshal(table, &all); e != nil {
		panic(e)
	}
}
func contains(s string, patterns []string) bool {
	for _, p := range patterns {
		if !strings.Contains(s, strings.ToLower(p)) {
			return false
		}
	}
	return true
}
func Decode(s string) string {
	for i := 0; i < 2; i++ {
		v, e := url.PathUnescape(s)
		if e != nil || v == s {
			break
		}
		s = v
	}
	return s
}
func Match(method, uri, contentType string, body []byte) []string {
	u := strings.ToLower(Decode(uri))
	path, _, _ := strings.Cut(u, "?")
	b := strings.ToLower(string(body))
	_, params, _ := mime.ParseMediaType(contentType)
	out := []string{}
	seen := map[string]bool{}
	for _, r := range all {
		if r.Method != "" && r.Method != method {
			continue
		}
		if !contains(path, r.Path) || !contains(u, r.URI) || !contains(b, r.Body) {
			continue
		}
		if r.BoundaryGT > 0 && len(params["boundary"]) <= r.BoundaryGT {
			continue
		}
		if !seen[r.CVE] {
			seen[r.CVE] = true
			out = append(out, r.CVE)
		}
	}
	return out
}
func Has(cves []string, cve string) bool {
	for _, c := range cves {
		if c == cve {
			return true
		}
	}
	return false
}
