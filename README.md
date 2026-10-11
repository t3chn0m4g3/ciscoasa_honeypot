# Ciscoasa v2

A Cisco ASA/FTD honeypot in Go, derived from Cymmetria's MIT-licensed Ciscoasa honeypot. It presents WebVPN, AnyConnect authentication, a minimal ASDM launcher and IKE negotiation. All logins are rejected. Incoming uploads are inert evidence and are never executed or used to make outbound connections.

## Run

Create `data/{identity,log,payloads}` writable by UID/GID 2000, then run `docker compose up --build`. Listeners are HTTPS 8443/tcp, IKE 500/udp and NAT-T 4500/udp. The image is a static binary in `scratch`, runs as UID 2000 and needs only the three writable mounts.

For a native binary: `go build -o asapot ./cmd/asapot`. Flags:

| Flag | Default |
| --- | --- |
| `-https` | `:8443` |
| `-ike` | `:500` |
| `-natt` | `:4500` |
| `-identity` | `/var/lib/ciscoasa/identity.json` |
| `-log` | `/var/log/ciscoasa/ciscoasa.json` |
| `-payloads` | `/var/lib/ciscoasa/payloads` |

Identity is generated once with an RSA-2048 self-signed certificate, ASA release, hostname, VPN groups and banner. Edit `identity.json` while stopped; malformed profiles are rejected. Keep the file private: it contains the TLS private key. No environment variables are required.

## Behavior and evidence

Browser requests receive the WebVPN portal and assets. `X-Aggregate-Auth: 1` requests receive AnyConnect XML. Init requests expose the selected release and groups; credential replies receive `Login failed.` with error ID 15. ASDM Basic authentication always returns 401.

Public request patterns identify CVE probes. Older flaws are tagged but answered as patched for the advertised ASA 9.16+ profile. Profiles before the 2025 chain fixes model a bounded, IP-bound bypass/upload session and return public error markers. Fixed profiles and direct protected uploads without a bypass session return 403. Attempted uploads are still captured as evidence. Uploads are streamed to SHA-256 names, at most 2 MiB each and 256 MiB total (including existing files after restart). Larger uploads within the HTTP body limit are hashed without being stored. HTTP bodies are limited to 4 MiB, headers to 32 KiB, active TCP connections to 1024 and 32 per IP, and simultaneous body-processing handlers to 32. Temporary payload bytes also count toward the disk quota.

IKEv1 Main/Aggressive negotiation supports 3DES or AES proposals, SHA1/SHA256, PSK/XAUTH-PSK and DH groups 2/14. Aggressive groups receive the same response behavior and a random hash, independent of the supplied group. Main Mode has no configured PSK, so it cannot establish an authenticated encrypted tunnel. IKEv2 supports AES-CBC 128/256, HMAC-SHA1/SHA256 and DH groups 2/14; a valid encrypted IKE_AUTH receives encrypted AUTHENTICATION_FAILED. Other proposals are rejected. NAT detection uses the local interface and peer address without outbound connections. Authenticated IKEv2 SAs can move from 500 to 4500, including a changed client UDP port. NAT-T requires a Non-ESP marker; ESP packets and keepalives are ignored. Sessions are limited to 4096, expire after one minute and open negotiations retransmit at 8-second intervals three times.

JSON lines contain UTC timestamps, event types, endpoints, protocol, credentials, CVE matches, a printable bounded payload and nested `asa.*` metadata. Heuristic spray/fragment matches indicate observed patterns, not proof of successful exploitation. AnyConnect, browser and ASDM logins are always refused. Secrets entered by clients are intentionally logged for honeypot analysis. Logs are reopened for each event to tolerate external rotation.

## Validation and limitations

Run `go test ./...`, `go vet ./...`, `go test -race ./...`, and short fuzz runs for `internal/ike` (`FuzzParse`) and `internal/rules` (`FuzzMatch`). Tests use inert evidence, not executable exploits.

Public fixtures are based on nmap's AnyConnect/IKE scripts, nuclei Cisco ASA matchers, ike-scan vendor/backoff databases and public OpenConnect traces. TLS is restricted to HTTP/1.1 over TLS 1.2; Go's TLS fingerprint is distinguishable from a real ASA. IKE vendor ordering follows the documented PIX/ASA family signature; nmap currently reports Cisco VPN Concentrator for the inherited proprietary VID, while AnyConnect reveals the exact ASA profile release. Generic nmap HTTP detection can identify the Go server independently of AnyConnect. ASDM is a minimal launcher, not a working Java application. There is no VPN data plane, no shell and no payload execution.

The T-Pot-pinned ewsposter parser needs the separate upstream compatibility PR to consume v2 payloads and report IKE metadata correctly; no local compatibility alias is emitted.

## License

MIT. Copyright (c) 2018 Cymmetria for the inherited assets; see LICENSE. Python v1 files remain as historical source and are not included or used by the v2 image.
