# PK95 DNS – design

A network-wide DNS filter in the spirit of AdGuard Home / Pi-hole, written in Go. It runs
standalone (own web UI with login) or under PK95 Core (app protocol v1: Core starts the
container, the admin UI lives in Core, the app sends events to Core).

## Runtime

| Env | Default | Meaning |
|---|---|---|
| `PK95DNS_LISTEN` | `0.0.0.0:8053` | HTTP: API, web UI, `/core/*` |
| `PK95DNS_DNS_LISTEN` | `:53` | DNS over UDP and TCP (dual stack) |
| `PK95DNS_DATA_DIR` | `/var/lib/pk95dns` | SQLite database `pk95dns.db`, list copies `lists/<id>.txt`, `initial-admin-password` |
| `PK95_CORE_MODE`, `PK95_CORE_URL`, `PK95_CORE_TOKEN` | – | Core mode, see app protocol |
| `TZ` | – | time zone (statistics buckets are UTC hours, display is the client's business) |

Container: `network_mode: host` (port 53 of the LXC and the real client addresses; Docker NAT
would hide the clients). Runs as root inside the container (port 53, no file capabilities in an
unprivileged LXC). Image `ghcr.io/philippkuhlmann/pk95-dns`, single static binary on
`debian:trixie-slim` (ca-certificates, tzdata).

If port 53 cannot be bound (e.g. systemd-resolved stub listener), the HTTP side runs anyway,
`/api/status.dns.error` explains it, event `dns.listen_failed` goes to Core, and binding is
retried every 30 s (`dns.listen_ok` once it works).

## Packages (module `pk95dns`)

```
main.go                 env/flags → app.Run
internal/config         Settings struct, Defaults(), Validate(), Merge (partial PUT)
internal/filter         rule parser, compiled RuleSet, Engine (atomic snapshots), services catalog,
                        SafeSearch table
internal/upstream       address parsing, plain/DoT/DoH/DoH3/DoQ upstreams, bootstrap, Router (modes,
                        conditional forwarding, private PTR, fallback, health)
internal/cache          DNS answer cache (LRU, TTL, min/max TTL)
internal/records        zones and DNS records: types, validation, compiled lookup Index (Compile, Resolve)
internal/store          SQLite (modernc.org/sqlite, WAL): settings, lists, custom rules, zones, records,
                        clients, users, sessions, query log, statistics tables
internal/querylog       buffered writer: batches entries into the store, pruning
internal/stats          in-memory hourly aggregation, flush to the store, summaries for /api/stats
internal/dnsserver      UDP/TCP listeners and the query pipeline, client matching, rate limit, /api/check
internal/lists          list download/update manager (ETag, size limit, last good copy, no https→http redirect), catalog
internal/api            HTTP API (docs/api.md), auth (sessions, login limiter), Core mode, web embed
internal/app            wiring: builds everything from the store, reloads on changes, events to Core
web/                    standalone SPA (vanilla JS, embedded): index.html, app.js, style.css
```

Dependencies: `github.com/miekg/dns`, `modernc.org/sqlite`, `golang.org/x/crypto/bcrypt`,
`github.com/quic-go/quic-go` (DNS-over-QUIC and DoH over HTTP/3). No others without need. `go test ./...` must pass with `-race`; `gofmt` clean.

## Query pipeline (dnsserver)

For every query (client IP `c`, name `n` lowercased without trailing dot, type `t`):

1. **Access**: `c` in `disallowed_clients` → REFUSED (reason `access`). `allowed_clients` not empty and
   `c` not in it → REFUSED.
2. **Rate limit** (`ratelimit` > 0): token bucket per client IP (burst = rate). Over the limit → the query
   is dropped without answer, logged as `refused`/`ratelimit` at most once per second per client.
3. **ANY** with `refuse_any` → NOTIMP (status `refused`, reason `any`).
4. **Client**: most specific configured client for `c` → effective filtering on/off, SafeSearch, blocked
   services (global unless the client overrides).
5. **Own zones and records** (always active, also when protection is off, never filtered): see
   "Local zones and records" below. Status `rewrite`, reason `zone` or `record`.
6. **Filtering** (when protection is on – global and not paused – and the client's filtering is on):
   `filter.Engine.Check` (order below). Block → blocked answer per `blocking_mode` (TTL `blocked_ttl`);
   hosts rule with an address → that address (status `rewrite`); SafeSearch → CNAME + resolved target
   (status `safesearch`); allow → continue with status `allowed`.
7. `disable_ipv6` and type AAAA → empty NOERROR (status `ok`).
8. **Cache** (`cache_enabled`): hit → answer with remaining TTL, `cached: true`.
9. **Upstream**: `upstream.Router.Resolve` (conditional forwarding, private PTR, mode, fallback). Failure →
   SERVFAIL (status `error`, reason `upstream`).
10. **Response check** (filtering active): CNAME targets in the answer are checked against block rules
    (CNAME cloaking); a match turns the answer into a blocked answer (status `blocked`, rule of the CNAME).
11. Cache store (only NOERROR/NXDOMAIN, not truncated), query log entry, statistics.

Blocked answers: `null_ip` → A `0.0.0.0` / AAAA `::`, other types empty NOERROR; `nxdomain` → NXDOMAIN with
a synthetic SOA in the authority section (TTL `blocked_ttl`); `refused` → REFUSED; `custom_ip` → the configured
address for its family, other types/families empty NOERROR.

Responses keep the client's EDNS0 UDP size; answers bigger than the UDP size are truncated (TC bit) so the
client retries over TCP. The upstream request uses a fresh ID and a copy of the question; DO bit when `dnssec`.

## Local zones and records

Package `internal/records` compiles enabled zones and records into an immutable index (swapped atomically on
every change) and answers lookups; the store keeps `zones` and `records` (docs/api.md → DNS zones and records).

**Zone answers** (longest enabled zone containing the query name; AA bit set, never forwarded):
- name with records: matching type → those records; CNAME at the name → CNAME, then the target is resolved
  (local index first, else cache/upstream, no filtering, max depth 5; a local CNAME loop or a longer chain →
  SERVFAIL); other type → NODATA (NOERROR, SOA in authority).
- apex: SOA and NS are synthesized (SOA `<primary_ns> hostmaster.<zone> <serial> 3600 600 604800 <ttl>`).
- name without records but with records below it (empty non-terminal) → NODATA.
- otherwise wildcard per RFC 4592: the closest encloser's `*.` child, if any, answers with the query name as owner
  (a wildcard never matches names that exist, and does not cover the encloser itself).
- otherwise NXDOMAIN with the SOA in authority (negative TTL = zone `ttl`).

**Single records** (no zone covers the name): exact name beats the most specific `*.` wildcard; matching type →
answer; CNAME → chase like above; A/AAAA asked and the name has only the other address family → empty NOERROR
(no SOA, split horizon); any other type without records, or no records → continue
with filtering/cache/upstream (as before).

**Additional section**: for MX and SRV answers the A/AAAA records of the targets from the index (zones and single
records). **Reverse lookups**: explicit PTR records first, then PTRs synthesized from A/AAAA records with
`ptr: true` (all names of that address; served like a PTR record at the reverse name: inside the reverse zone
when one covers it – not at all when that zone is disabled –, else as a single record), then the normal
private-PTR routing. The NS answer at a zone apex also gets the A/AAAA of `primary_ns` from the index. TXT values over 255 bytes are split
into several strings. TTLs come from the records; local answers are never put into the cache.
DNSSEC: zones are not signed; DS/DNSKEY/RRSIG queries inside a zone get NODATA. No zone transfers: AXFR/IXFR for a
name inside a zone or with single records → REFUSED.

## Filtering (filter package)

### Rule syntax (lists and custom rules)

| Line | Meaning |
|---|---|
| `! …`, `# …`, `[Adblock Plus …]`, empty | comment |
| `||example.org^` | block `example.org` and all subdomains |
| `|example.org^`, `example.org` (bare domain line) | block exactly `example.org` |
| `*.example.org` | block all subdomains (not the domain itself) |
| `@@||example.org^` (and the other forms with `@@`) | allow |
| `/regex/` | block when the regular expression (RE2) matches the name; `@@/regex/` allows |
| `||ads*.example.org^` | `*` wildcard inside a pattern (compiled to a regex) |
| `0.0.0.0 a.example b.example`, `127.0.0.1 …`, `:: …`, `::1 …` | hosts syntax: block exactly these names |
| `192.168.1.5 nas.lan` | hosts syntax with another address: answer with that address (rewrite); in lists downloaded over plain `http://` it blocks the name instead (their content is not integrity protected) |
| `…$important` | beats allow rules |
| `…$dnstype=AAAA|HTTPS` | only for these query types (`~TYPE` excludes) |

Other `$` options (`$client`, `$dnsrewrite`, `$denyallow`, `$badfilter`, `$ctag`, …) and cosmetic rules
(`##`, `#@#`, `#$#`) make the line invalid (ignored, counted, reported for custom rules). `localhost`,
`localhost.localdomain`, `local`, `broadcasthost`, `ip6-*` entries in hosts files are skipped silently.
Domains are lowercased, IDNs must be punycode. Max 1000 rules that compile to a regex (`/regex/` and `*` wildcards inside a pattern) per source and 20000 across all sources (rest invalid).

### Decision order (`Engine.Check`)

1. custom block rule with `$important` → block
2. custom allow rule → allow
3. SafeSearch (client/global enabled and engine enabled) → rewrite to the safe host
4. custom block rule (hosts rule with address → rewrite)
5. blocked service → block (`blocked_service`)
6. list block rule with `$important` → block
7. allow list rule or `@@` rule in any list → allow
8. list block rule (hosts rule with address → rewrite)
9. nothing → no match

`Rule` in the result is the original rule text (custom rules) or a canonical form (`||domain^`, `domain`,
`*.domain`, `/regex/`, `ip domain`) for lists, so a large list costs memory for one key per rule only.

### SafeSearch

Rewrites (CNAME): Google search domains (`www.google.<tld>` and `google.<tld>` for the known country TLDs)
→ `forcesafesearch.google.com`; `www.bing.com`, `bing.com` → `strict.bing.com`; `duckduckgo.com`,
`www.duckduckgo.com`, `start.duckduckgo.com` → `safe.duckduckgo.com`; YouTube (`www.youtube.com`,
`m.youtube.com`, `youtubei.googleapis.com`, `youtube.googleapis.com`, `www.youtube-nocookie.com`)
→ `restrictmoderate.youtube.com`; Yandex search domains → `familysearch.yandex.ru`; `pixabay.com`,
`www.pixabay.com` → `safesearch.pixabay.com`.

### Blocked services

A built-in catalog (`filter.Services()`), each service a set of `||domain^` rules: at least YouTube, TikTok,
Instagram, Facebook, WhatsApp, X (Twitter), Snapchat, Pinterest, Reddit, LinkedIn, Discord, Telegram,
Signal, Netflix, Twitch, Disney+, Prime Video, Spotify, Steam, Epic Games, Roblox, Minecraft, PlayStation
Network, Xbox Live, Amazon, eBay, Temu, AliExpress, ChatGPT, Tinder, 9GAG, VK.

## Upstreams (upstream package)

Address forms: see `docs/api.md` → Settings. Transports (`Spec.Protocol()` label in brackets):

| Address | Transport |
|---|---|
| `9.9.9.9[:53]`, `udp://…` | plain DNS over UDP, TCP retry on truncation (`DNS`) |
| `tcp://…` | plain DNS over TCP only (`DNS/TCP`) |
| `tls://host[:853]` | DNS-over-TLS, RFC 7858, pool of up to 4 idle connections, one query per connection at a time (`DoT`) |
| `https://host[:443][/path]` | DNS-over-HTTPS, RFC 8484 POST over HTTP/2 (HTTP/1.1 if the server offers nothing else); never upgraded to HTTP/3 by itself (`DoH`) |
| `h3://host[:443][/path]` | DNS-over-HTTPS over HTTP/3 (QUIC), same request and checks as DoH (`DoH3`) |
| `quic://host[:853]` | DNS-over-QUIC, RFC 9250 (`DoQ`) |

Plain addresses need an IP; encrypted ones take an IP or a host name (path default `/dns-query`).

**DNS-over-QUIC** (`quic-go`): ALPN `doq`, TLS 1.3. One long-lived QUIC connection per upstream, shared
by all queries; each query on its own bidirectional stream: 2-byte length prefix + message with ID 0 (the
caller's ID is restored in the answer), then STREAM FIN; the answer is read up to the server's FIN, at
most 2 + 65535 bytes, and must be exactly one length-prefixed message with ID 0 – otherwise the connection is
closed with `DOQ_PROTOCOL_ERROR`. Cancelled/timed-out queries reset their stream with
`DOQ_REQUEST_CANCELLED`. The connection is dialed on demand, one dial at a time, shared by every query that
waits for it and detached from their contexts (bounded by the upstream timeout): a query that is cancelled –
the loser in `parallel` mode, a client that gave up – only stops waiting, the handshake completes and the
connection serves the next query. It closes after 30 s idle (no keep-alives) and is dialed again; when a
query fails because the shared connection was closed in the meantime (idle timeout, `CONNECTION_CLOSE` with
any DoQ error code, stateless reset) it is sent once more on a fresh connection. A server that lost its
state silently (restart without stateless reset, anycast change) leaves the connection open locally: when a
query times out after at least half the upstream timeout and nothing at all arrived on its connection since
it started, the connection is detached – new queries dial a fresh one – and closed once its last query in
flight is done (in-flight queries are counted per connection). `Close` closes the connection with
`DOQ_NO_ERROR` after the last query in flight. Never 0-RTT: 0-RTT data can be replayed by an attacker.

**DoH3** uses `http3.Transport` (one shared connection per host, dialed detached from the request). The
transport keeps that connection when a request only times out, so the upstream tracks the connections it
dialed: on a timeout (same rule as DoQ: at least half the upstream timeout, no response header on that
connection since the request started) the connection is closed with `H3_NO_ERROR`, and the transport dials
a fresh one for the next request. Requests still waiting on it fail, but they have received nothing either.

**Hardening** of the encrypted transports (there is deliberately no option to weaken any of it):

- Certificates are always verified against the system roots and the configured host (IP hosts must be in
  the IP SANs). No "skip verification" option. TLS 1.2 minimum for DoT/DoH, TLS 1.3 for DoQ/DoH3 (QUIC).
- DoH/DoH3: no redirects (a redirect could downgrade or leak the query to another host – it is an error),
  no cookie jar, no HTTP proxy (`Proxy: nil`: a proxy from the environment would see every query target and
  DNS must not depend on it), no compression, response header limit 64 KiB, idle pool of 4 connections
  (90 s), TLS handshake and response header timeouts equal to the upstream timeout. Request: POST
  `application/dns-message` with `Accept: application/dns-message`, ID 0. Response: status 200,
  `Content-Type: application/dns-message` (parameters allowed), body ≤ 65535 bytes, otherwise an error.
- Every transport (plain UDP/TCP included) checks that the answer has the QR bit and answers the question
  of the query (name case-insensitive, type, class); mismatches are errors. Plain UDP/TCP and DoT also
  require the query ID (UDP answers with another ID are ignored, as miekg/dns does).
- **Padding** (RFC 7830, block-length strategy of RFC 8467): queries over DoT, DoH, DoH3 and DoQ are padded
  to a multiple of 128 octets. This is done on a copy (`Exchange` never modifies the caller's message): an
  OPT record (UDP size 1232) is added when the query has none – and removed from the answer again –,
  existing padding options are replaced, padding in the answer is stripped. Plain DNS is never padded.

**Bootstrap**: host names of encrypted upstreams are resolved through the `bootstrap` servers (plain DNS,
system resolver when `bootstrap` is empty – never this server itself), cached for the answer TTL, at least
60 s and at most 1 h (system resolver: 5 min). Bootstrap answers are not trusted for integrity: a forged
address only makes the connection fail the certificate check, so the bootstrap servers can see which
upstream is used but cannot redirect queries. To keep a forged answer from causing a long outage, the TTL
is capped and the cached addresses of a host are dropped when connecting to every one of them failed (TCP
for DoT/DoH, QUIC handshake for DoQ/DoH3; not when the dial was cancelled), so the next query resolves the
name again.
The defaults avoid bootstrap for the fallback by using IP endpoints whose certificates carry the IP
(`https://9.9.9.9/dns-query`, `https://1.1.1.1/dns-query`).

**`encrypted_only`** (default `true`): `upstreams` and `fallback` must be `tls://`, `https://`, `h3://` or
`quic://` (checked by `config.Validate` with `upstream.Encrypted`). `conditional` and `private_upstreams`
are meant for the LAN (router, Fritz!Box): they may stay plain, but only to a private IP
(`upstream.LANOnly`: 10/8, 172.16/12, 192.168/16, 100.64/10, 127/8, 169.254/16, fc00::/7, fe80::/10, ::1) –
otherwise e.g. a conditional rule for `com` to `8.8.8.8` would send queries unencrypted over the internet.
Public servers there must be encrypted as well. The router itself does not enforce it – the settings
validation does.

Modes: `load_balance` picks an upstream weighted by inverse average RTT (unknown/failed ones get a chance
too), `parallel` asks all and takes the first good answer, `sequential` tries in order. An answer is "good"
unless it is SERVFAIL/REFUSED or an error. When all fail, `fallback` upstreams are tried in order. A query
has a budget of 2× `upstream_timeout`; when fallbacks exist, the main upstreams get the budget minus one
timeout so the fallback is always asked. In `load_balance`/`sequential` mode each try gets at most a fair
share of the time left (remaining / upstreams left), and connecting to a host with several addresses gives
each address such a share too, so one upstream or address that silently drops packets cannot use up the
whole budget.

Routing: longest matching `conditional` domain wins (its upstream only, no fallback). Reverse lookups for
private ranges (any name below their reverse zone, e.g. DNS-SD browse names) with `private_ptr` → `private_upstreams` (or NXDOMAIN when empty). Everything else → main
upstreams.

Health per upstream: queries, failures, average RTT (EWMA), last error, `ok` = last answer good.
The app sends `upstream.down` when every main upstream failed for 60 s and `upstream.up` on recovery.

## Storage

SQLite in WAL mode, one connection pool, `busy_timeout`. Tables (see `internal/store`): `settings` (key,
JSON value), `lists`, `custom_rules` (single row), `zones`, `records` (schema v2 migrated the v1 `rewrites`
with the same ids), `clients`, `users`, `sessions` (token hash),
`queries` (query log, indexes on `ts`, `name`, `client_ip`), `stats_hours` (hour, totals),
`stats_top` (hour, kind, key, count – top 100 per kind and hour). List contents live in
`<data>/lists/<id>.txt` so a restart does not need the network.

Query log: entries are buffered and written in batches (every second or 500 entries); retention
`querylog_hours`, pruned every 10 minutes. `anonymize_ip` stores IPv4 with the last octet 0 and IPv6 /48.
Statistics: current hour in memory, flushed every minute (upsert) and on shutdown; retention `stats_days`.

## Events to Core

`upstream.down` (critical), `upstream.up` (info), `lists.update_failed` (warning, once per list until it works
again), `dns.listen_failed` (critical), `dns.listen_ok` (info). Buffered and retried for up to one hour.

## Core manifest

```json
{ "id": "dns", "name": "PK95 DNS", "version": "1.1.0", "protocol": 1, "icon": "shield",
  "menu": [
    { "key": "overview", "label": "Übersicht", "icon": "home" },
    { "key": "log", "label": "Abfragen", "icon": "list" },
    { "key": "lists", "label": "Blocklisten", "icon": "shield" },
    { "key": "rules", "label": "Eigene Regeln", "icon": "pencil" },
    { "key": "records", "label": "DNS-Einträge", "icon": "link" },
    { "key": "services", "label": "Dienste", "icon": "lock" },
    { "key": "clients", "label": "Clients", "icon": "user" },
    { "key": "settings", "label": "Einstellungen", "icon": "cog" }
  ],
  "capabilities": ["events", "backup"],
  "events": ["upstream.down", "upstream.up", "lists.update_failed", "dns.listen_failed", "dns.listen_ok"] }
```

## First start

Settings = defaults. Lists: "AdGuard DNS filter"
(`https://adguardteam.github.io/HostlistsRegistry/assets/filter_1.txt`, enabled) and
"OISD Small" (`https://small.oisd.nl/`, disabled) are created and downloaded in the background.
Standalone: account `admin` with a random password (see docs/api.md).
