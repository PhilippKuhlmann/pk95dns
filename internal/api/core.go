package api

import (
	"bytes"
	"io/fs"
	"net/http"
	"path"
	"strings"

	"pk95dns/web"
)

// Manifest is the answer of GET /core/manifest (docs/design.md → Core manifest).
type Manifest struct {
	ID           string     `json:"id"`
	Name         string     `json:"name"`
	Version      string     `json:"version"`
	Protocol     int        `json:"protocol"`
	Icon         string     `json:"icon"`
	Menu         []MenuItem `json:"menu"`
	Capabilities []string   `json:"capabilities"`
	Events       []string   `json:"events"`
}

// MenuItem is one page of the Core sidebar.
type MenuItem struct {
	Key   string `json:"key"`
	Label string `json:"label"`
	Icon  string `json:"icon"`
}

// Event types sent to Core.
const (
	EventUpstreamDown     = "upstream.down"
	EventUpstreamUp       = "upstream.up"
	EventListUpdateFailed = "lists.update_failed"
	EventDNSListenFailed  = "dns.listen_failed"
	EventDNSListenOK      = "dns.listen_ok"
)

// ManifestFor returns the manifest for version.
func ManifestFor(version string) Manifest {
	return Manifest{
		ID: "dns", Name: "PK95 DNS", Version: version, Protocol: 1, Icon: "shield",
		Menu: []MenuItem{
			{Key: "overview", Label: "Übersicht", Icon: "home"},
			{Key: "log", Label: "Abfragen", Icon: "list"},
			{Key: "lists", Label: "Blocklisten", Icon: "shield"},
			{Key: "rules", Label: "Eigene Regeln", Icon: "pencil"},
			{Key: "records", Label: "DNS-Einträge", Icon: "link"},
			{Key: "services", Label: "Dienste", Icon: "lock"},
			{Key: "clients", Label: "Clients", Icon: "user"},
			{Key: "settings", Label: "Einstellungen", Icon: "cog"},
		},
		Capabilities: []string{"events", "backup"},
		Events: []string{
			EventUpstreamDown, EventUpstreamUp, EventListUpdateFailed, EventDNSListenFailed, EventDNSListenOK,
		},
	}
}

func (a *API) handleHealth(w http.ResponseWriter, _ *http.Request) {
	if err := a.d.Store.Ping(); err != nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{
			"ok": false, "version": a.d.Version, "error": "Datenbank antwortet nicht.",
		})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "version": a.d.Version})
}

func (a *API) handleManifest(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, ManifestFor(a.d.Version))
}

func (a *API) handleBackupPrepare(w http.ResponseWriter, r *http.Request) {
	// Bring the buffered data into the database first.
	if a.d.QueryLog != nil {
		a.d.QueryLog.Flush()
	}
	if a.d.Stats != nil {
		if err := a.d.Stats.Flush(); err != nil {
			internalError(w, r, err)
			return
		}
	}
	if err := a.d.Store.Checkpoint(); err != nil {
		internalError(w, r, err)
		return
	}
	writeNoContent(w)
}

// coreNote is the page at "/" in Core mode.
const coreNote = `<!doctype html>
<html lang="de">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="color-scheme" content="light dark">
<title>PK95 DNS</title>
</head>
<body style="font-family: system-ui, sans-serif; max-width: 36rem; margin: 4rem auto; padding: 0 1rem; line-height: 1.5">
<h1 style="font-size: 1.4rem">PK95 DNS</h1>
<p>PK95 DNS wird über PK95 Core verwaltet. Bitte öffne die Oberfläche von PK95 Core.</p>
</body>
</html>
`

// handleWeb serves the embedded web UI (standalone) or the Core note.
func (a *API) handleWeb(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		writeError(w, http.StatusMethodNotAllowed, "Methode nicht erlaubt.")
		return
	}
	if a.d.CoreMode {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-cache")
		_, _ = w.Write([]byte(coreNote))
		return
	}
	name := strings.TrimPrefix(path.Clean("/"+r.URL.Path), "/")
	if name == "" || name == "index.html" {
		a.serveFile(w, r, "index.html")
		return
	}
	if st, err := fs.Stat(web.FS, name); err != nil || st.IsDir() {
		// Client-side routes fall back to the app.
		a.serveFile(w, r, "index.html")
		return
	}
	a.serveFile(w, r, name)
}

func (a *API) serveFile(w http.ResponseWriter, r *http.Request, name string) {
	data, err := fs.ReadFile(web.FS, name)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	switch path.Ext(name) {
	case ".html":
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
	case ".js":
		w.Header().Set("Content-Type", "text/javascript; charset=utf-8")
	case ".css":
		w.Header().Set("Content-Type", "text/css; charset=utf-8")
	case ".svg":
		w.Header().Set("Content-Type", "image/svg+xml")
	case ".png":
		w.Header().Set("Content-Type", "image/png")
	}
	// The files carry no content hash in their names: always revalidate.
	w.Header().Set("Cache-Control", "no-cache")
	http.ServeContent(w, r, name, a.d.StartedAt, bytes.NewReader(data))
}
