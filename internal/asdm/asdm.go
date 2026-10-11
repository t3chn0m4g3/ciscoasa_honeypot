package asdm

import (
	"github.com/t3chn0m4g3/ciscoasa_honeypot/internal/eventlog"
	"net/http"
	"strings"
)

func Handle(w http.ResponseWriter, r *http.Request, e *eventlog.Event) {
	e.Type = "asdm.request"
	switch r.URL.Path {
	case "/admin/public/index.html":
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write([]byte(`<html><head><title>Cisco ASDM</title></head><body><a href="/admin/public/asdm.jnlp">Run Cisco ASDM</a></body></html>`))
	case "/admin/public/asdm.jnlp", "/admin/asdm.jnlp":
		w.Header().Set("Content-Type", "application/x-java-jnlp-file")
		w.Write([]byte(`<?xml version="1.0"?><jnlp><information><title>Cisco ASDM</title><vendor>Cisco Systems, Inc.</vendor></information><security><all-permissions/></security><resources/><application-desc main-class="com.cisco.launcher.Launcher"/></jnlp>`))
	default:
		if u, p, ok := r.BasicAuth(); ok {
			e.Type = "asdm.login"
			e.Username = u
			e.Password = p
		}
		w.Header().Set("WWW-Authenticate", `Basic realm="Cisco ASDM"`)
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte("Authorization Required"))
	}
}
func Path(path string) bool { return path == "/admin" || strings.HasPrefix(path, "/admin/") }
