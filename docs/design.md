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
                        SafeSearch table, Rewrites table (local records)
internal/upstream       address parsing, plain/DoT/DoH upstreams, bootstrap, Router (modes,
                        conditional forwarding, private PTR, fallback, health)
internal/cache          DNS answer cache (LRU, TTL, min/max TTL)
internal/store          SQLite (modernc.org/sqlite, WAL): settings, lists, custom rules, rewrites,
                        clients, users, sessions, query log, statistics tables
internal/querylog       buffered writer: batches entries into the store, pruning
internal/stats          in-memory hourly aggregation, flush to the store, summaries for /api/stats
internal/dnsserver      UDP/TCP listeners and the query pipeline, client matching, rate limit, /api/check
internal/lists          list download/update manager (ETag, size limit, last good copy), catalog
internal/api            HTTP API (docs/api.md), auth (sessions, login limiter), Core mode, web embed
internal/app            wiring: builds everything from the store, reloads on changes, events to Core
web/                    standalone SPA (vanilla JS, embedded): index.html, app.js, style.css
```

Dependencies: `github.com/miekg/dns`, `modernc.org/sqlite`, `golang.org/x/crypto/bcrypt`. No others
without need. `go test ./...` must pass with `-race`; `gofmt` clean.

## Query pipeline (dnsserver)

For every query (client IP `c`, name `n` lowercased without trailing dot, type `t`):

1. **Access**: `c` in `disallowed_clients` → REFUSED (reason `access`). `allowed_clients` not empty and
   `c` not in it → REFUSED.
2. **Rate limit** (`ratelimit` > 0): token bucket per client IP (burst = rate). Over the limit → the query
   is dropped without answer, logged as `refused`/`ratelimit` at most once per second per client.
3. **ANY** with `refuse_any` → NOTIMP (status `refused`, reason `any`).
4. **Client**: most specific configured client for `c` → effective filtering on/off, SafeSearch, blocked
   services (global unless the client overrides).
5. **Local records** (rewrites, always active, also when protection is off): exact match beats `*.` wildcard.
   IP answers only for the matching family (A → IPv4 records, AAAA → IPv6 records; the other family gets an
   empty NOERROR if the name has records but none of that family). Host name answers become a CNAME plus the
   resolved target (through the pipeline from step 5, max depth 5). Status `rewrite`.
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
| `192.168.1.5 nas.lan` | hosts syntax with another address: answer with that address (rewrite) |
| `…$important` | beats allow rules |
| `…$dnstype=AAAA|HTTPS` | only for these query types (`~TYPE` excludes) |

Other `$` options (`$client`, `$dnsrewrite`, `$denyallow`, `$badfilter`, `$ctag`, …) and cosmetic rules
(`##`, `#@#`, `#$#`) make the line invalid (ignored, counted, reported for custom rules). `localhost`,
`localhost.localdomain`, `local`, `broadcasthost`, `ip6-*` entries in hosts files are skipped silently.
Domains are lowercased, IDNs must be punycode. Max 1000 regex rules per source (rest invalid).

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

Address forms: see `docs/api.md` → Settings. Plain DNS uses UDP with TCP retry on truncation; `tcp://`
only TCP; DoT (`tls://host[:853]`, certificate checked against the host name); DoH (`https://…`, RFC 8484
POST `application/dns-message`, HTTP/2 when offered). Host names of DoT/DoH upstreams are resolved through
the bootstrap servers (system resolver when `bootstrap` is empty), cached for the answer TTL (min 60 s).

Modes: `load_balance` picks an upstream weighted by inverse average RTT (unknown/failed ones get a chance
too), `parallel` asks all and takes the first good answer, `sequential` tries in order. An answer is "good"
unless it is SERVFAIL/REFUSED or an error. When all fail, `fallback` upstreams are tried in order.

Routing: longest matching `conditional` domain wins (its upstream only, no fallback). Reverse lookups for
private ranges with `private_ptr` → `private_upstreams` (or NXDOMAIN when empty). Everything else → main
upstreams.

Health per upstream: queries, failures, average RTT (EWMA), last error, `ok` = last answer good.
The app sends `upstream.down` when every main upstream failed for 60 s and `upstream.up` on recovery.

## Storage

SQLite in WAL mode, one connection pool, `busy_timeout`. Tables (see `internal/store`): `settings` (key,
JSON value), `lists`, `custom_rules` (single row), `rewrites`, `clients`, `users`, `sessions` (token hash),
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
{ "id": "dns", "name": "PK95 DNS", "version": "1.0.0", "protocol": 1, "icon": "shield",
  "menu": [
    { "key": "overview", "label": "Übersicht", "icon": "home" },
    { "key": "log", "label": "Abfragen", "icon": "list" },
    { "key": "lists", "label": "Blocklisten", "icon": "shield" },
    { "key": "rules", "label": "Eigene Regeln", "icon": "pencil" },
    { "key": "rewrites", "label": "Lokale Einträge", "icon": "link" },
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
