package rules

import (
	"strings"
	"testing"
)

func TestRules(t *testing.T) {
	cases := []struct{ method, uri, ct, body, cve string }{{"GET", "/+CSCOE+/logon.html", "", "", ""}, {"GET", "/+CSCOU+/%252e%252e/+CSCOE+/files/file_action.html", "", "", "CVE-2025-20362"}, {"POST", "/", "application/xml", "<host-scan-reply>placeholder", "CVE-2018-0101"}, {"POST", "/+CSCOE+/files/file_action.html", "multipart/form-data; boundary=" + strings.Repeat("b", 8193), "inert", "CVE-2025-20333"}}
	for _, c := range cases {
		got := Match(c.method, c.uri, c.ct, []byte(c.body))
		if c.cve == "" && len(got) > 0 || c.cve != "" && !Has(got, c.cve) {
			t.Error(got, c.cve)
		}
	}
}
func FuzzMatch(f *testing.F) {
	f.Add("GET", "/+CSCOE+/logon.html", "", []byte{})
	f.Fuzz(func(t *testing.T, m, u, c string, b []byte) {
		if len(u)+len(c)+len(b) > 4<<20 {
			t.Skip()
		}
		Match(m, u, c, b)
	})
}
