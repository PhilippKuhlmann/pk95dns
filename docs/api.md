# PK95 DNS – HTTP API

One JSON API serves both the built-in web UI (standalone mode) and the PK95 Core module
(Core mode, app protocol v1, see `PK95Core/docs/app-protocol.md`). Default listen address
`0.0.0.0:8053` (`PK95DNS_LISTEN`).

## Conventions

- Request and response bodies are JSON (`Content-Type: application/json`).
- Timestamps are Unix **milliseconds** (integers). `0` means "never/none".
- IDs are integers.
- Errors: `{"error": "German message"}` with a fitting status. Validation errors are
  `422 {"error": "Bitte Eingaben prüfen.", "fields": {"<field>": "German message"}}`. Field
  names are the JSON keys of the request body; for array items `upstreams.2`, for nested
  objects `safesearch.google`.
- `401 {"error": …}` without valid authentication, `404` for unknown ids, `413` for bodies over 2 MiB.
- Writing requests (`POST`, `PUT`, `DELETE`) must carry `Content-Type: application/json`, otherwise `415`
  (CSRF guard for the cookie session; Core always sends it, also on DELETE).

## Authentication

**Core mode** (`PK95_CORE_MODE=1`): every `/api/*` and `/core/*` route except `GET /core/health`
requires `Authorization: Bearer <PK95_CORE_TOKEN>` (constant-time comparison, tokens shorter
than 32 chars never match). The login routes and the web UI are off: `/api/login` answers
`401 {"error": "PK95 DNS wird über PK95 Core verwaltet"}`, `/` serves a short HTML note.

**Standalone mode**: session cookie `pk95dns_session` (HttpOnly, SameSite=Strict, Secure when the
request came over TLS, 7 days). On first start the account `admin` gets a random password,
written to `<data dir>/initial-admin-password` (0600) and logged once. The file is removed after
the first password change.

| Route | Body | Answer |
|---|---|---|
| `POST /api/login` | `{"username","password"}` | `200 {"username"}` + cookie; `401` wrong; `429` after 5 failures per client in 15 min (client = IPv4 address or IPv6 /64; attempts in flight count, so parallel requests cannot exceed the limit) |
| `POST /api/logout` | – | `204` |
| `GET /api/me` | – | `200 {"username","core_mode":false}` or `401` |
| `POST /api/password` | `{"current","new"}` | `204`; `422` fields `current` (wrong) / `new` (min. 12 chars) |

## Core protocol routes

- `GET /core/health` → `200 {"ok":true,"version"}` when the database answers (also when port 53
  could not be bound – that shows up in `/api/status` and as event `dns.listen_failed`).
- `GET /core/manifest` → manifest, see `docs/design.md`.
- `POST /core/backup/prepare` → `204` after `PRAGMA wal_checkpoint(TRUNCATE)`.

## Status and protection

### `GET /api/status`

```json
{
  "version": "1.0.0",
  "core_mode": true,
  "started_at": 1762700000000,
  "dns": { "listen": "0.0.0.0:53", "udp": true, "tcp": true, "error": "" },
  "protection": { "enabled": true, "paused_until": 0 },
  "rules": { "lists": 3, "list_rules": 152340, "custom_rules": 12, "rewrites": 4, "services": 2 },
  "cache": { "enabled": true, "entries": 1840, "hits": 9120, "misses": 4410 },
  "upstreams": [
    { "address": "https://dns.quad9.net/dns-query", "ok": true, "avg_ms": 18.4, "queries": 3010, "failures": 2, "last_error": "" }
  ]
}
```

`dns.error` is a German message when binding failed (e.g. "Port 53 ist belegt: …"); the server retries every 30 s.
`protection.paused_until` > 0: blocking is paused until then. `enabled: false` with `paused_until: 0`: off until switched on.

### `POST /api/protection`

Body `{"enabled": false, "minutes": 10}` pauses for 10 minutes; `minutes: 0` (or missing) switches off until
switched on again. `{"enabled": true}` switches on. Answer: the `protection` object from `/api/status`.

## Statistics

### `GET /api/stats?hours=24`

`hours`: `24`, `168` (7 days) or `720` (30 days); other values → 24. Series: hourly for 24 and 168, daily for 720.

```json
{
  "hours": 24,
  "granularity": "hour",
  "totals": { "queries": 13530, "blocked": 2104, "blocked_pct": 15.6, "cached": 9120, "safesearch": 12, "services": 40, "avg_ms": 6.2 },
  "series": [ { "t": 1762696800000, "queries": 610, "blocked": 92 } ],
  "top_domains": [ { "name": "example.org", "count": 812 } ],
  "top_blocked": [ { "name": "ads.example.net", "count": 330 } ],
  "top_clients": [ { "ip": "192.168.1.20", "name": "Laptop", "count": 4210, "blocked": 600 } ],
  "top_upstreams": [ { "address": "https://dns.quad9.net/dns-query", "count": 3010, "avg_ms": 18.4 } ]
}
```

`blocked` counts statuses `blocked` and `blocked_service`. Top lists have at most 20 entries. `name` of a client
is the configured client name, else its reverse-DNS host name, else `""`.

### `DELETE /api/stats` → `204` (resets all statistics)

## Query log

### `GET /api/querylog?limit=50&before=0&search=&client=&status=all`

- `limit` 1–500 (default 50); `before`: only entries with `id < before` (paging, newest first).
- `search`: substring of the domain (case-insensitive). `client`: exact IP or client name.
- `status`: `all`, `blocked` (`blocked`, `blocked_service`), `allowed` (`ok`, `allowed`), `rewritten`
  (`rewrite`, `safesearch`), `failed` (`error`, `refused`).

```json
{
  "items": [
    {
      "id": 99812, "ts": 1762700012345,
      "client_ip": "192.168.1.20", "client_name": "Laptop",
      "name": "ads.example.net", "qtype": "A",
      "status": "blocked", "reason": "list", "rule": "||ads.example.net^",
      "list_id": 1, "list_name": "AdGuard DNS filter", "service": "",
      "upstream": "", "rcode": "NOERROR", "answer": "0.0.0.0",
      "elapsed_ms": 0.12, "cached": false
    }
  ],
  "next_before": 99762
}
```

Status vocabulary (also used by `/api/check`):

| status | meaning |
|---|---|
| `ok` | forwarded to an upstream (or answered from cache: `cached: true`) |
| `allowed` | an allow rule (`@@…` or allow list) matched, then forwarded |
| `blocked` | block rule (custom rules or a block list) |
| `blocked_service` | a blocked service (`service` = service id) |
| `safesearch` | rewritten to the SafeSearch host |
| `rewrite` | local DNS record or hosts rule with an address (`rule`) |
| `refused` | client not allowed, ANY refused, or rate limit |
| `error` | all upstreams failed (SERVFAIL) |

`reason`: `list`, `custom`, `service`, `safesearch`, `rewrite`, `access`, `any`, `ratelimit`, `upstream`, `""`.
`answer`: short text, comma separated (`"93.184.216.34, 2606:2800::1"`, `"CNAME forcesafesearch.google.com"`, `""`).
`next_before`: id for the next page, `0` when there is none.

### `DELETE /api/querylog` → `204`

## Block and allow lists

List object:

```json
{ "id": 1, "name": "AdGuard DNS filter", "url": "https://…/filter_1.txt", "kind": "block",
  "enabled": true, "rule_count": 61234, "updated_at": 1762690000000, "last_error": "", "updating": false }
```

| Route | Body | Answer |
|---|---|---|
| `GET /api/lists` | – | `200 [list…]` ordered by kind, then name |
| `GET /api/lists/catalog` | – | `200 [{"name","url","kind","description"}]` well-known lists to pick from |
| `POST /api/lists` | `{"name","url","kind","enabled"}` | `201 list` (enabled lists are downloaded right away, async) |
| `PUT /api/lists/{id}` | same | `200 list` (URL change or enable → download) |
| `DELETE /api/lists/{id}` | – | `204` |
| `POST /api/lists/refresh` | – | `202 {"ok":true}` downloads all enabled lists now (async; poll `GET /api/lists`, field `updating`) |
| `POST /api/lists/{id}/refresh` | – | `202 {"ok":true}` |

Validation: `name` 1–80 chars; `url` `http(s)://…` max 2000 chars and unique; `kind` `block`|`allow`.
Downloads: max 64 MiB, timeout 60 s, conditional GET (`ETag`/`Last-Modified`); the last good copy stays
in use when a download fails (`last_error`). At most 5 redirects, and never from `https://` to `http://`
(`last_error` „Download fehlgeschlagen: … Weiterleitung von https auf http abgelehnt“). `http://` lists are
still accepted but are not integrity protected: their hosts lines with a non-null address
(`192.168.1.5 nas.lan`) block the name instead of rewriting it; only `https://` lists can rewrite. UIs
should recommend `https://`. Changing the `url` while a download runs downloads the new address
afterwards; the result of the old one is dropped.

## Custom rules

`GET /api/rules` and `PUT /api/rules` with `{"text": "…"}` (max 1 MiB) both answer:

```json
{ "text": "||ads.example.com^\n@@||good.example.com^", "rule_count": 2,
  "invalid": [ { "line": 7, "text": "||bad$foo", "error": "Unbekannte Option: foo" } ] }
```

Invalid lines are saved but ignored. `POST /api/rules/quick` `{"domain": "x.example.com", "action": "block"|"allow"|"remove"}`
adds `||domain^` or `@@||domain^` (removing the opposite and duplicates for exactly that domain) or removes both;
answers like `GET /api/rules`. `422 fields.domain` for an invalid domain.

Rule syntax: see `docs/design.md` → Filtering.

### `GET /api/check?name=ads.example.net&type=A&client=192.168.1.20`

Runs the filter pipeline without asking an upstream. `type` default `A`, `client` optional (IP).

```json
{ "name": "ads.example.net", "type": "A", "client_ip": "192.168.1.20", "client_name": "Laptop",
  "status": "blocked", "reason": "list", "rule": "||example.net^", "list_id": 1, "list_name": "AdGuard DNS filter",
  "service": "", "answer": "0.0.0.0" }
```

`status` is `ok` when nothing matched. `422 fields.name` for an invalid domain.

## Local DNS records (rewrites)

```json
{ "id": 3, "domain": "nas.home.lan", "answer": "192.168.1.10", "enabled": true, "created_at": 1762690000000 }
```

`GET /api/rewrites` → `200 [rewrite…]` (ordered by domain); `POST /api/rewrites` → `201`; `PUT /api/rewrites/{id}` → `200`; `DELETE` → `204`.
`domain`: host name, or `*.example.lan` for all subdomains (not the domain itself). `answer`: IPv4, IPv6 or a host
name (answered as CNAME, the target is resolved further). Exact entries win over wildcards.

## Blocked services

`GET /api/services` →

```json
{ "services": [ { "id": "tiktok", "name": "TikTok", "group": "social" } ], "blocked": ["tiktok"] }
```

Groups: `social`, `messenger`, `video`, `music`, `gaming`, `shopping`, `ai`, `other`.
`PUT /api/services` `{"blocked": ["tiktok"]}` → same shape. Unknown ids → `422 fields.blocked`.

## Clients

Client object:

```json
{ "id": 2, "name": "Kinder-Tablet", "ids": ["192.168.1.40", "192.168.50.0/24"],
  "use_global_settings": false, "filtering_enabled": true,
  "safesearch": { "enabled": true, "google": true, "bing": true, "duckduckgo": true, "youtube": true, "yandex": true, "pixabay": true },
  "use_global_services": false, "blocked_services": ["tiktok"], "created_at": 1762690000000 }
```

- `GET /api/clients` → `{"clients": [client…], "recent": [{"ip","hostname","client_id","name","queries","blocked","last_seen"}]}`
  `recent`: clients seen in the last 24 h (from statistics), most queries first, max 100. `hostname` via reverse DNS (cached), `client_id` 0 if not configured.
- `POST /api/clients` → `201`, `PUT /api/clients/{id}` → `200`, `DELETE /api/clients/{id}` → `204`.
- Validation: `name` 1–80 chars and unique; `ids` 1–50 entries, each an IP or CIDR, not used by another client.
- The most specific matching id wins (single IP before the narrowest CIDR).
- `use_global_settings: true`: `filtering_enabled` and `safesearch` come from the global settings.
  `use_global_services: true`: the globally blocked services apply.

## Settings

`GET /api/settings` → the full object. `PUT /api/settings` takes **any subset** of the keys and answers the full
object (`422` on invalid values, nothing is saved then). `blocked_services` and `protection_*` are not part of it
(own routes).

```json
{
  "upstreams": ["https://dns.quad9.net/dns-query", "https://cloudflare-dns.com/dns-query"],
  "fallback": ["https://9.9.9.9/dns-query", "https://1.1.1.1/dns-query"],
  "bootstrap": ["9.9.9.9", "1.1.1.1"],
  "encrypted_only": true,
  "upstream_mode": "load_balance",
  "upstream_timeout_ms": 4000,
  "conditional": [ { "domain": "fritz.box", "upstream": "192.168.178.1" } ],
  "private_ptr": true,
  "private_upstreams": ["192.168.178.1"],
  "cache_enabled": true, "cache_size": 10000, "cache_min_ttl": 0, "cache_max_ttl": 86400,
  "blocking_mode": "null_ip", "blocking_ipv4": "", "blocking_ipv6": "", "blocked_ttl": 10,
  "ratelimit": 50, "refuse_any": true, "dnssec": false, "disable_ipv6": false,
  "allowed_clients": ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16", "::1/128", "fc00::/7", "fe80::/10"],
  "disallowed_clients": [],
  "querylog_enabled": true, "querylog_hours": 168, "anonymize_ip": false,
  "stats_days": 30,
  "lists_update_hours": 24,
  "safesearch": { "enabled": false, "google": true, "bing": true, "duckduckgo": true, "youtube": true, "yandex": true, "pixabay": true }
}
```

| Key | Values |
|---|---|
| `upstreams` | 1–20 addresses, see the table below. Default `https://dns.quad9.net/dns-query`, `https://cloudflare-dns.com/dns-query` |
| `fallback` | 0–10 addresses, used when all `upstreams` fail. Default `https://9.9.9.9/dns-query`, `https://1.1.1.1/dns-query` (by IP: no bootstrap needed, the certificates carry the IPs) |
| `bootstrap` | 0–10 plain IP addresses (optional `:port`), only resolve the host names of encrypted upstreams (the certificate check protects against forged answers; answers are cached 60 s – 1 h and dropped when no resolved address can be reached). Default `9.9.9.9`, `1.1.1.1` |
| `encrypted_only` | default `true`: every entry of `upstreams` and `fallback` must be `tls://`, `https://`, `h3://` or `quic://` (error per entry, e.g. `upstreams.1`: „Nur verschlüsselte Upstreams erlaubt (tls://, https://, h3://, quic://). Klartext-DNS ist nur für bedingte Weiterleitung und private PTR-Anfragen vorgesehen.“). `conditional[].upstream` and `private_upstreams` may be plain only to a private IP (10/8, 172.16/12, 192.168/16, 100.64/10, 127/8, 169.254/16, fc00::/7, fe80::/10, ::1); otherwise they must be encrypted too (error e.g. `conditional.0.upstream` / `private_upstreams.1`: „Bei „Nur verschlüsselte Upstreams“ ist Klartext-DNS nur zu einer privaten IP-Adresse (LAN) erlaubt. Für öffentliche Server tls://, https://, h3:// oder quic:// verwenden.“). With `encrypted_only: false` every valid address is accepted |
| `upstream_mode` | `load_balance` (weighted by response time), `parallel` (all at once, fastest wins), `sequential` (in order) |
| `upstream_timeout_ms` | 500–30000 |
| `conditional` | 0–50 `{domain, upstream}`: queries for the domain and its subdomains go to that upstream |
| `private_ptr` | `true`: reverse lookups for private addresses (RFC 1918, CGNAT, ULA, link-local), including any name below these reverse zones such as DNS-SD browse names (`lb._dns-sd._udp.0.1.168.192.in-addr.arpa`), never go to public upstreams; they go to `private_upstreams` or are answered NXDOMAIN |
| `private_upstreams` | 0–10 addresses |
| `cache_size` | 0–1000000 entries; `cache_min_ttl` 0–3600; `cache_max_ttl` 0–604800 (0 = no limit), min ≤ max |
| `blocking_mode` | `null_ip` (0.0.0.0 / ::), `nxdomain`, `refused`, `custom_ip` (needs `blocking_ipv4` and/or `blocking_ipv6`) |
| `blocked_ttl` | 0–86400 seconds |
| `ratelimit` | queries per second per client IP, 0 = off, max 100000 |
| `refuse_any` | answer `ANY` queries with NOTIMP |
| `dnssec` | set the DO bit towards upstreams |
| `disable_ipv6` | answer `AAAA` with an empty NOERROR |
| `allowed_clients` | IPs/CIDRs (max 200) that may query; empty = everyone (open resolver!) |
| `disallowed_clients` | IPs/CIDRs (max 200), always refused |
| `querylog_hours` | 1–2160; `stats_days` 1–90; `lists_update_hours` 0 (off), 1–168 |

Upstream address forms (`upstreams`, `fallback`, `private_upstreams`, `conditional[].upstream`):

| Form | Protocol | Notes |
|---|---|---|
| `9.9.9.9`, `9.9.9.9:53`, `[2620:fe::fe]:53`, `udp://1.1.1.1` | DNS | plain UDP (TCP on truncation), IP only, not encrypted |
| `tcp://1.1.1.1[:53]` | DNS/TCP | plain TCP, IP only, not encrypted |
| `tls://dns.quad9.net[:853]`, `tls://1.1.1.1` | DoT | DNS-over-TLS (RFC 7858) |
| `https://dns.quad9.net[:443]/dns-query` | DoH | DNS-over-HTTPS (RFC 8484) over HTTP/2; path default `/dns-query` |
| `h3://cloudflare-dns.com[:443]/dns-query` | DoH3 | DNS-over-HTTPS over HTTP/3 (QUIC); path default `/dns-query` |
| `quic://dns.adguard-dns.com[:853]`, `quic://94.140.14.14` | DoQ | DNS-over-QUIC (RFC 9250), default port 853 |

Encrypted forms accept a host name or an IP (`[v6]` in brackets); the certificate is always checked against
it (no option to skip). Unknown schemes: „Unbekanntes Protokoll: … (erlaubt: udp, tcp, tls, https, h3, quic)“.

## Cache and upstream test

- `DELETE /api/cache` → `204`.
- `POST /api/upstreams/test` `{"upstreams": ["…"], "bootstrap": ["…"]}` (1–20 addresses, all forms incl. `h3://`
  and `quic://`; `encrypted_only` does not apply to the test) →
  `200 {"results": [{"upstream","ok","ms","error"}]}`. Asks each upstream for `example.org A` in parallel, 4 s per
  upstream, answers within 6 s. Invalid addresses come back with `ok: false` and an error, not as 422.
