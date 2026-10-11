package anyconnect

import (
	"encoding/xml"
	"fmt"
	"github.com/t3chn0m4g3/ciscoasa_honeypot/internal/eventlog"
	"github.com/t3chn0m4g3/ciscoasa_honeypot/internal/identity"
	"strings"
)

type Request struct {
	XMLName xml.Name `xml:"config-auth"`
	Type    string   `xml:"type,attr"`
	Version string   `xml:"version"`
	Device  struct {
		Platform string `xml:",chardata"`
		ID       string `xml:"unique-id,attr"`
	} `xml:"device-id"`
	Group  string `xml:"group-select"`
	Opaque struct {
		Group string `xml:"tunnel-group"`
	} `xml:"opaque"`
	Auth struct {
		Username string `xml:"username"`
		Password string `xml:"password"`
	} `xml:"auth"`
}

func Parse(b []byte) (Request, error) {
	var r Request
	e := xml.Unmarshal(b, &r)
	if r.Group == "" {
		r.Group = r.Opaque.Group
	}
	return r, e
}
func Escape(s string) string { var b strings.Builder; xml.EscapeText(&b, []byte(s)); return b.String() }
func Init(p *identity.Profile, group string) string {
	requested := group
	group = p.Groups[0].Name
	alias := p.Groups[0].Alias
	for _, g := range p.Groups {
		if g.Name == requested || g.Alias == requested {
			group = g.Name
			alias = g.Alias
			break
		}
	}
	var opts strings.Builder
	for _, g := range p.Groups {
		fmt.Fprintf(&opts, `<option value="%s">%s</option>`, Escape(g.Name), Escape(g.Alias))
	}
	return fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?><config-auth client="vpn" type="auth-request" aggregate-auth-version="2"><version who="sg">%s</version><opaque is-for="sg"><tunnel-group>%s</tunnel-group><group-alias>%s</group-alias><config-hash>%s</config-hash></opaque><auth id="main"><title>SSL VPN Service</title><banner>%s</banner><message>Please enter your username and password.</message><form method="post" action="/"><select name="group_list" label="GROUP:">%s</select><input type="text" name="username" label="Username:"/><input type="password" name="password" label="Password:"/></form></auth></config-auth>`, Escape(p.Version), Escape(group), Escape(alias), Escape(p.ConfigHash), Escape(p.Banner), opts.String())
}
func Failure(p *identity.Profile, parseError bool) string {
	id, text := "15", "Login failed."
	if parseError {
		id, text = "98", "VPN Server could not parse request."
	}
	return fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?><config-auth client="vpn" type="auth-request" aggregate-auth-version="2"><version who="sg">%s</version><auth id="main"><error id="%s" param1="" param2="">%s</error></auth></config-auth>`, Escape(p.Version), id, text)
}
func Metadata(r Request) *eventlog.Client {
	return &eventlog.Client{Version: r.Version, Platform: r.Device.Platform, DeviceID: r.Device.ID}
}
