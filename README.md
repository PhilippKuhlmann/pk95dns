# PK95 DNS

DNS-Filter für das ganze Netz, nach dem Vorbild von AdGuard Home und Pi-hole. Ein einzelnes Go-Programm
beantwortet die DNS-Anfragen aller Geräte, blockiert Werbung, Tracker und unerwünschte Dienste und fragt
alles andere verschlüsselt bei Quad9 oder Cloudflare an. Läuft unter [PK95 Core](https://github.com/PhilippKuhlmann/pk95core)
oder eigenständig mit eigener Oberfläche.

- Oberfläche (eigenständig): `http://<server>:8053`, Benutzer `admin`
- Startpasswort: `/var/lib/pk95dns/initial-admin-password` (die Datei verschwindet, sobald das Passwort
  unter *Einstellungen* geändert wurde)
- DNS: Port 53, UDP und TCP

## Funktionsumfang

- **Blocklisten** im Adblock-, Hosts- und Domain-Format, mit Katalog bekannter Listen (AdGuard, OISD,
  Hagezi, Steven Black …). Vorgabe: „AdGuard DNS filter“ aktiv, „OISD Small“ vorbereitet. Aktualisierung
  alle 24 Stunden mit bedingtem Abruf (`ETag`); scheitert ein Abruf, bleibt die letzte gute Fassung aktiv.
  Erlaubnislisten heben Einträge der Blocklisten auf.
- **Eigene Regeln** mit derselben Syntax, ungültige Zeilen werden mit Grund angezeigt. Im Abfrageprotokoll
  lässt sich jede Domain mit einem Klick sperren oder freigeben.
- **Lokale Einträge** (`nas.home.lan → 192.168.1.10`, auch `*.home.lan` und Namen als CNAME). Sie gelten
  immer, auch bei pausiertem Schutz.
- **Dienste sperren:** über 50 Dienste mit einem Schalter, etwa TikTok, Instagram, YouTube, Netflix, Steam,
  Roblox und ChatGPT.
- **SafeSearch** für Google, Bing, DuckDuckGo, YouTube, Yandex und Pixabay.
- **Clients:** Geräte oder Netze (IP oder CIDR) mit eigenen Einstellungen für Filter, SafeSearch und
  gesperrte Dienste, zum Beispiel ein Kinder-Tablet.
- **Upstreams** verschlüsselt über DNS-over-HTTPS, DNS-over-TLS, DNS-over-QUIC und DoH über HTTP/3, mit
  Lastverteilung, parallel oder der Reihe nach, Ersatz-Upstreams, bedingter Weiterleitung (`fritz.box` an
  den Router) und privaten PTR-Anfragen an den Router. Zertifikate werden immer geprüft.
- **Schutz pausieren** für 1 Minute bis 24 Stunden oder ganz ausschalten.
- **Abfrageprotokoll** mit Suche und Filtern (gesperrt, erlaubt, umgeschrieben, fehlgeschlagen), Statistik
  über 24 Stunden, 7 und 30 Tage mit Top-Domains, Top-Sperren, Top-Clients und Antwortzeiten.
- **Schutz vor Missbrauch:** Standardmäßig antworten nur private Netze (kein offener Resolver), Rate-Limit
  pro Client, `ANY`-Anfragen werden abgelehnt, CNAME-Cloaking wird erkannt.
- **Cache** mit einstellbarer Größe und minimaler/maximaler TTL.

**Nicht enthalten (anders als AdGuard Home):** eigener DHCP-Server, DNS-over-HTTPS/TLS als Server für die
Clients, Cosmetic-Regeln und `$dnsrewrite`/`$client`-Optionen, mehrere Benutzer.

## Betrieb unter PK95 Core

Unter Core läuft PK95 DNS als Container `ghcr.io/philippkuhlmann/pk95-dns` im LXC von Core
(Katalog `dns`):

1. In Core unter *Apps* „PK95 DNS“ installieren. Core startet den Container und zeigt die Seiten von
   PK95 DNS in seinem Menü (Übersicht, Abfragen, Blocklisten, Eigene Regeln, Lokale Einträge, Dienste,
   Clients, Einstellungen).
2. **Port 53 des LXC muss frei sein.** Der Container läuft im Host-Netz (`network_mode: host`), damit er
   Port 53 belegt und die echten Adressen der Geräte sieht. Läuft im LXC `systemd-resolved` mit
   Stub-Listener, siehe [Port 53 ist belegt](#port-53-ist-belegt). Ob der DNS-Server lauscht, zeigt die
   Übersicht; sonst kommt das Ereignis `dns.listen_failed`.
3. **Im Router die IP des LXC als DNS-Server eintragen**, bei der Fritz!Box unter *Heimnetz → Netzwerk →
   Netzwerkeinstellungen → IPv4-Einstellungen → Lokaler DNS-Server*. Andere Router: DNS-Server im DHCP.
   Die Geräte übernehmen das mit der nächsten DHCP-Erneuerung (oder WLAN kurz trennen).
4. Damit `fritz.box` und die Namen der Geräte weiter aufgelöst werden: unter *Einstellungen* eine bedingte
   Weiterleitung `fritz.box → 192.168.178.1` und den Router als privaten Upstream eintragen.

- **API auf Port 8053** (8080 belegt Core). Im Core-Modus gibt es keine eigene Oberfläche und kein Login:
  `/api/*` nimmt nur den Token von Core an, die Seiten rendert Core.
- **Ereignisse an Core:** `upstream.down`, `upstream.up`, `lists.update_failed`, `dns.listen_failed`,
  `dns.listen_ok`. Core verschickt daraus die Benachrichtigungen.
- **Sicherung:** Core sichert das Volume `/var/lib/pk95dns` (Datenbank im WAL-Modus, vorher
  `POST /core/backup/prepare`).

## Eigenständig mit Docker

Voraussetzungen: Linux-Server mit Docker, Port 53 frei. Das Host-Netz ist Pflicht: Mit Docker-NAT
käme jede Anfrage von der Adresse der Bridge, Client-Einstellungen und Statistik wären wertlos.

```sh
docker run -d --name pk95-dns --restart unless-stopped --network host \
  -v pk95dns_data:/var/lib/pk95dns -e TZ=Europe/Berlin \
  ghcr.io/philippkuhlmann/pk95-dns:latest
```

Oder mit Compose ([`docker-compose.yml`](docker-compose.yml) aus diesem Repo):

```sh
docker compose up -d
```

Startpasswort lesen (steht auch einmal im Log):

```sh
docker exec pk95-dns cat /var/lib/pk95dns/initial-admin-password
```

Dann `http://<server>:8053` öffnen, als `admin` anmelden und unter *Einstellungen* ein eigenes Passwort
setzen (mindestens 12 Zeichen). Danach die IP des Servers im Router als DNS-Server eintragen (siehe oben).

| Variable | Vorgabe | Bedeutung |
|---|---|---|
| `PK95DNS_LISTEN` | `0.0.0.0:8053` | API und Oberfläche |
| `PK95DNS_DNS_LISTEN` | `:53` | DNS über UDP und TCP |
| `PK95DNS_DATA_DIR` | `/var/lib/pk95dns` | Datenbank `pk95dns.db`, Listenkopien `lists/`, Startpasswort |
| `TZ` | – | Zeitzone für das Log |

Die Oberfläche läuft nur über HTTP. Port 8053 deshalb nicht ins Internet freigeben, von außen per VPN
oder SSH-Tunnel (`ssh -L 8053:127.0.0.1:8053 root@server`) oder hinter einem Reverse Proxy mit TLS.

**Update:** `docker compose pull && docker compose up -d`. Die Datenbank wird beim Start migriert.

**Backup:** Container stoppen und das Volume sichern:

```sh
docker compose stop dns
docker run --rm -v pk95dns_pk95dns_data:/data -v "$PWD":/backup debian:trixie-slim \
  tar czf /backup/pk95dns-$(date +%F).tar.gz -C /data .
docker compose start dns
```

Der Name des Volumes richtet sich nach dem Projektordner, `docker volume ls` zeigt ihn.

## Port 53 ist belegt

Auf Debian/Ubuntu mit `systemd-resolved` lauscht dessen Stub-Listener auf `127.0.0.53:53`. Die API läuft
trotzdem, `/api/status` und die Übersicht melden „Port 53 ist belegt“, und PK95 DNS versucht es alle 30
Sekunden erneut. Abhilfe:

```sh
mkdir -p /etc/systemd/resolved.conf.d
printf '[Resolve]\nDNSStubListener=no\n' > /etc/systemd/resolved.conf.d/pk95dns.conf
ln -sf /run/systemd/resolve/resolv.conf /etc/resolv.conf
systemctl restart systemd-resolved
```

Andere Kandidaten: `dnsmasq`, ein laufendes AdGuard Home oder Pi-hole. `ss -lunp 'sport = :53'` zeigt, wer
den Port belegt.

## Regeln

Gilt für Blocklisten und eigene Regeln:

| Zeile | Wirkung |
|---|---|
| `\|\|example.org^` | sperrt `example.org` und alle Subdomains |
| `example.org`, `\|example.org^` | sperrt genau `example.org` |
| `*.example.org` | sperrt alle Subdomains, nicht die Domain selbst |
| `@@\|\|example.org^` | erlaubt (hebt Sperren auf) |
| `/^ads[0-9]+\./` | regulärer Ausdruck (RE2), höchstens 1000 pro Liste |
| `\|\|ads*.example.org^` | `*` als Platzhalter |
| `0.0.0.0 a.example b.example` | Hosts-Format: sperrt genau diese Namen |
| `192.168.1.5 nas.lan` | Hosts-Format mit Adresse: antwortet mit dieser Adresse |
| `…$important` | gewinnt gegen Erlaubnisregeln |
| `…$dnstype=AAAA\|HTTPS` | nur für diese Abfragetypen (`~TYPE` schließt aus) |
| `! …`, `# …` | Kommentar |

Reihenfolge: eigene `$important`-Sperren, eigene Erlaubnisse, SafeSearch, eigene Sperren, gesperrte Dienste,
`$important` aus Listen, Erlaubnisse aus Listen, Sperren aus Listen. Andere `$`-Optionen und Cosmetic-Regeln
(`##`) sind ungültig und werden ignoriert. *Eigene Regeln → Domain prüfen* (`/api/check`) zeigt, welche Regel greift.

Gesperrte Anfragen bekommen standardmäßig `0.0.0.0` bzw. `::`. Alternativ: `NXDOMAIN`, `REFUSED` oder eine
eigene Adresse (*Einstellungen → Blockieren*).

## API

Eine JSON-API für die eigene Oberfläche und für Core: [`docs/api.md`](docs/api.md). Aufbau, Abfrageablauf
und Speicherung: [`docs/design.md`](docs/design.md).

## Entwicklung

```sh
go test -race -count=1 ./...
test -z "$(gofmt -l .)" && go vet ./...
```

Lokal ohne root auf hohen Ports starten:

```sh
PK95DNS_LISTEN=127.0.0.1:18053 PK95DNS_DNS_LISTEN=127.0.0.1:15353 PK95DNS_DATA_DIR=./data go run .
dig @127.0.0.1 -p 15353 example.org
```

Das Startpasswort steht dann in `./data/initial-admin-password`. Core-Modus zum Testen:
`PK95_CORE_MODE=1 PK95_CORE_TOKEN=<mindestens 32 Zeichen> PK95_CORE_URL=http://127.0.0.1:8080`.

| Paket | Inhalt |
|---|---|
| `internal/dnsserver` | UDP/TCP-Listener, Abfrageablauf, Clients, Rate-Limit |
| `internal/filter` | Regel-Parser, Regelwerk, Dienste, SafeSearch, lokale Einträge |
| `internal/upstream` | DNS, DoT, DoH, DoH3, DoQ, Bootstrap, Router |
| `internal/lists` | Download und Aktualisierung der Listen, Katalog |
| `internal/cache` | Antwort-Cache |
| `internal/querylog`, `internal/stats` | Abfrageprotokoll und Statistik |
| `internal/store` | SQLite |
| `internal/api` | HTTP-API, Anmeldung, Core-Modus |
| `internal/app` | Zusammenbau, Ereignisse an Core |
| `web/` | Oberfläche ohne externe Abhängigkeiten |

Das Image baut GitHub Actions (`.github/workflows/image.yml`) für `linux/amd64` und `linux/arm64`; ein Tag
`v1.2.3` setzt die Version, die Core prüft.
