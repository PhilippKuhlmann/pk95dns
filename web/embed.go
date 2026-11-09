// Package web holds the standalone web UI (vanilla JS single page app), embedded into the binary.
package web

import "embed"

// FS contains index.html, app.js, style.css, theme.js and the other static files.
//
//go:embed index.html app.js style.css theme.js
var FS embed.FS
