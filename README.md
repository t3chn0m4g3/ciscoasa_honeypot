# Ciscoasa v2.0.1

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

Public request patterns are recorded with their identifiers. The advertised profile determines replies for the simulated portal/upload workflow. Direct protected uploads without a matching session return 403. Uploaded content is retained as inert evidence. Uploads are streamed to SHA-256 names, at most 2 MiB each and 256 MiB total (including existing files after restart). Larger uploads within the HTTP body limit are hashed without being stored. HTTP bodies are limited to 4 MiB, headers to 32 KiB and active TCP connections to 1024 and 32 per IP. At most 64 requests are admitted concurrently, four per source IP. Bodies have a five-second read deadline and are read before a processing worker is taken. Requests beyond the concurrency limits close the connection. Temporary payload bytes also count toward the disk quota.

IKEv1 Main/Aggressive negotiation supports 3DES or AES proposals, SHA1/SHA256, PSK/XAUTH-PSK and DH groups 2/14. Aggressive groups receive the same response behavior and a random hash, independent of the supplied group. Main Mode has no configured PSK, so it cannot establish an authenticated encrypted tunnel. IKEv2 supports AES-CBC 128/256, HMAC-SHA1/SHA256 and DH groups 2/14; a valid encrypted IKE_AUTH receives encrypted AUTHENTICATION_FAILED. Other proposals are rejected. NAT detection uses a stable private address derived from the persistent profile and the peer address without outbound connections. Authenticated IKEv2 SAs can move from 500 to 4500, including a changed client UDP port. NAT-T requires a Non-ESP marker; ESP packets and keepalives are ignored. Sessions are limited to 4096 and expire after one minute. Each request is answered at most once; a repeated request receives the cached response. Request hashes are kept with the cached responses. Both UDP listeners share 20 packets/second globally, 10 per source network and 20 per source IP. Source networks are IPv4 /24 or IPv6 /64. Response bytes are limited to 64 KiB/second globally and 8 KiB/second per source network; a response also stays within three times its request size, including UDP/IP headers and the NAT-T marker.

JSON lines contain UTC timestamps, event types, endpoints, credentials, printable payload text and nested `asa.*` metadata. Control characters in single-line values are escaped, and resulting values stay within their field limits. IKE payload text is limited to 1024 bytes. Requests omitted by the input limits are summarized per source and listener in one-minute windows (`ike.ratelimit` or `http.ratelimit`, with `asa.count`). Summary tables hold at most 4096 entries and use a shared remainder counter thereafter. Credentials supplied by clients are recorded for honeypot analysis.

The active JSONL log is limited to 64 MiB. A complete line that would exceed that limit is omitted until rotation makes space; the limit also applies after a restart. The log stays open in append mode and is reopened when its path is replaced or removed. External `copytruncate` rotation is supported.

## Validation and limitations

Run `go test ./...`, `go vet ./...`, `go test -race ./...`, and short fuzz runs for `internal/ike` (`FuzzParse`) and `internal/rules` (`FuzzMatch`). Tests use inert evidence.

Public protocol fixtures are based on nmap, nuclei, ike-scan vendor databases and public OpenConnect traces. TLS uses HTTP/1.1 over TLS 1.2. IKE vendor ordering follows the documented PIX/ASA family signature; nmap reports Cisco VPN Concentrator for the inherited proprietary VID, while AnyConnect reports the profile release. ASDM is a minimal launcher. There is no VPN data plane, shell or payload execution.

The T-Pot-pinned ewsposter parser needs the separate upstream compatibility PR to consume v2 payloads and report IKE metadata correctly; no local compatibility alias is emitted.

## License

MIT. Copyright (c) 2018 Cymmetria for the inherited assets; see LICENSE. Python v1 files remain as historical source and are not included or used by the v2 image.
