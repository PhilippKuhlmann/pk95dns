"use strict";
// PK95 DNS – standalone web UI. Talks only to the JSON API (docs/api.md).
// Domains, client names and list texts come from the network or other users. They reach the
// DOM exclusively through textContent and setAttribute, never as HTML.

const app = document.getElementById("app");
const nf = new Intl.NumberFormat("de-DE");
const SVG_NS = "http://www.w3.org/2000/svg";

// --- DOM helpers -----------------------------------------------------------

function h(tag, props, ...kids) {
  const el = document.createElement(tag);
  applyProps(el, props);
  append(el, kids);
  return el;
}

function s(tag, attrs, ...kids) {
  const el = document.createElementNS(SVG_NS, tag);
  applyProps(el, attrs, true);
  append(el, kids);
  return el;
}

function applyProps(el, props, svg) {
  for (const [k, v] of Object.entries(props || {})) {
    if (v === undefined || v === null || v === false) continue;
    if (k.startsWith("on") && typeof v === "function") el.addEventListener(k.slice(2), v);
    else if (k === "class") el.setAttribute("class", v);
    else if (svg || k.startsWith("aria-") || k.startsWith("data-") || k === "title" || k === "role" || k === "for" || k === "list") el.setAttribute(k, v);
    else el[k] = v;
  }
}

function append(el, kids) {
  for (const kid of kids.flat(Infinity)) {
    if (kid === undefined || kid === null || kid === false) continue;
    el.append(kid instanceof Node ? kid : document.createTextNode(String(kid)));
  }
}

// replaceChildren that accepts nested arrays and skips null/false like h().
function fill(el, ...kids) {
  el.replaceChildren();
  append(el, kids);
}

let uid = 0;
const nextId = (p) => `${p || "f"}${++uid}`;

// --- API -------------------------------------------------------------------

class ApiError extends Error {
  constructor(message, status, fields) {
    super(message);
    this.status = status;
    this.fields = fields || null;
  }
}

const isAbort = (e) => e && e.name === "AbortError";

function statusMessage(status) {
  if (status === 404) return "Nicht gefunden. Vielleicht wurde der Eintrag gerade entfernt.";
  if (status === 413) return "Die Daten sind zu groß.";
  if (status === 429) return "Zu viele Versuche. Bitte warte ein paar Minuten.";
  if (status >= 500) return `Serverfehler (${status}). Bitte versuche es gleich noch einmal.`;
  return `Fehler ${status}`;
}

// Every writing request carries Content-Type: application/json (CSRF guard), also DELETE.
async function api(path, opts = {}) {
  const method = opts.method || "GET";
  const init = { method, headers: {}, credentials: "same-origin", signal: opts.signal, cache: "no-store" };
  if (method !== "GET") {
    init.headers["Content-Type"] = "application/json";
    if (opts.body !== undefined) init.body = JSON.stringify(opts.body);
    else if (method === "POST" || method === "PUT") init.body = "{}";
  }
  let res;
  try {
    res = await fetch("api/" + path, init);
  } catch (e) {
    if (isAbort(e)) throw e;
    throw new ApiError("Keine Verbindung zu PK95 DNS. Läuft der Dienst?", 0);
  }
  let data = null;
  if (res.status !== 204) {
    try { data = await res.json(); } catch { /* empty or not JSON */ }
  }
  if (res.status === 401 && !opts.noAuthRedirect) {
    onUnauthorized();
    throw new ApiError((data && data.error) || "Bitte melde dich an.", 401);
  }
  if (!res.ok) throw new ApiError((data && data.error) || statusMessage(res.status), res.status, data && data.fields);
  return data;
}

// --- Formatting ------------------------------------------------------------

function fmtCompact(n) {
  n = n || 0;
  if (n >= 1e6) return (n / 1e6).toLocaleString("de-DE", { maximumFractionDigits: 1 }) + " Mio.";
  if (n >= 100000) return (n / 1e3).toLocaleString("de-DE", { maximumFractionDigits: 0 }) + " Tsd.";
  return nf.format(n);
}

function fmtAxis(n) {
  if (n >= 1e6) return (n / 1e6).toLocaleString("de-DE", { maximumFractionDigits: 1 }) + " M";
  if (n >= 10000) return (n / 1e3).toLocaleString("de-DE", { maximumFractionDigits: 1 }) + " T";
  return nf.format(n);
}

function fmtMs(ms) {
  if (ms === undefined || ms === null) return "–";
  if (ms === 0) return "0 ms";
  if (ms < 0.1) return "<0,1 ms";
  if (ms < 10) return ms.toLocaleString("de-DE", { maximumFractionDigits: 1 }) + " ms";
  if (ms < 1000) return Math.round(ms) + " ms";
  return (ms / 1000).toLocaleString("de-DE", { maximumFractionDigits: 2 }) + " s";
}

function fmtPct(p) {
  if (!p) return "0 %";
  if (p < 0.1) return "<0,1 %";
  return p.toLocaleString("de-DE", { maximumFractionDigits: 1 }) + " %";
}

const pct = (part, total) => (total > 0 ? (part / total) * 100 : 0);

const fmtTime = new Intl.DateTimeFormat("de-DE", { hour: "2-digit", minute: "2-digit" });
const fmtTimeSec = new Intl.DateTimeFormat("de-DE", { hour: "2-digit", minute: "2-digit", second: "2-digit" });
const fmtDay = new Intl.DateTimeFormat("de-DE", { day: "2-digit", month: "2-digit" });
const fmtWeekday = new Intl.DateTimeFormat("de-DE", { weekday: "short", day: "2-digit", month: "2-digit" });
const fmtDayLong = new Intl.DateTimeFormat("de-DE", { weekday: "short", day: "2-digit", month: "2-digit", year: "numeric" });
const fmtFull = new Intl.DateTimeFormat("de-DE", { day: "2-digit", month: "2-digit", year: "numeric", hour: "2-digit", minute: "2-digit", second: "2-digit" });

let rtf = null;
try { rtf = new Intl.RelativeTimeFormat("de", { numeric: "auto", style: "short" }); } catch { /* optional */ }

function fmtAgo(ms) {
  if (!ms) return "nie";
  const sec = (Date.now() - ms) / 1000;
  if (sec < 45) return "gerade eben";
  const steps = [[60, "minute", 60], [3600, "hour", 24], [86400, "day", 30], [2592000, "month", 12], [31536000, "year", Infinity]];
  for (const [div, unit, limit] of steps) {
    const n = Math.round(sec / div);
    if (n < limit) return rtf ? rtf.format(-Math.max(1, n), unit) : `vor ${n} ${unit}`;
  }
  return fmtFull.format(new Date(ms));
}

function isToday(d) {
  const now = new Date();
  return d.getFullYear() === now.getFullYear() && d.getMonth() === now.getMonth() && d.getDate() === now.getDate();
}

function fmtLogTime(ms) {
  const d = new Date(ms);
  return isToday(d) ? fmtTimeSec.format(d) : `${fmtDay.format(d)}, ${fmtTimeSec.format(d)}`;
}

function fmtRemaining(ms) {
  const total = Math.max(0, Math.ceil(ms / 1000));
  const hh = Math.floor(total / 3600);
  const mm = Math.floor((total % 3600) / 60);
  const ss = total % 60;
  const two = (n) => String(n).padStart(2, "0");
  return hh > 0 ? `${hh}:${two(mm)}:${two(ss)} Std.` : `${mm}:${two(ss)} Min.`;
}

function plural(n, one, many) {
  return `${nf.format(n)} ${n === 1 ? one : many}`;
}

const lines = (text) => text.split(/\r?\n/).map((x) => x.trim()).filter(Boolean);

// --- Feedback: toasts and dialogs ------------------------------------------

let toastBox = null;

function toast(msg, kind) {
  if (!toastBox || !toastBox.isConnected) {
    toastBox = h("div", { class: "toasts", "aria-live": "polite" });
    document.body.append(toastBox);
  }
  const t = h("div", { class: "toast" + (kind === "error" ? " error" : ""), role: kind === "error" ? "alert" : "status" }, msg);
  toastBox.append(t);
  while (toastBox.children.length > 3) toastBox.firstChild.remove();
  setTimeout(() => t.remove(), kind === "error" ? 6500 : 3500);
}

const toastError = (e) => { if (!isAbort(e) && !(e && e.status === 401)) toast(e.message || String(e), "error"); };

// Dialogs close on a click next to them. The press must start there too, otherwise selecting
// text inside the dialog and releasing outside would close it.
let backdropPress = null;
const isBackdrop = (e) => {
  if (!(e.target instanceof HTMLDialogElement)) return false;
  const box = e.target.getBoundingClientRect();
  return e.clientX < box.left || e.clientX > box.right || e.clientY < box.top || e.clientY > box.bottom;
};
document.addEventListener("pointerdown", (e) => { backdropPress = isBackdrop(e) ? e.target : null; });
document.addEventListener("click", (e) => {
  if (backdropPress && e.target === backdropPress && isBackdrop(e)) e.target.close();
  backdropPress = null;
});

function openDialog(title, content, opts = {}) {
  const heading = h("h1", { id: nextId("dh") }, title);
  const dlg = h("dialog", { class: opts.wide ? "wide" : "", "aria-labelledby": heading.id },
    h("div", { class: "dialog-body" }, heading, content));
  const opener = document.activeElement;
  dlg.addEventListener("close", () => {
    dlg.remove();
    if (opts.onClose) opts.onClose();
    if (opener && opener.isConnected && typeof opener.focus === "function") opener.focus();
  });
  document.body.append(dlg);
  dlg.showModal();
  return dlg;
}

// Asks before something irreversible. action() may throw; the message is shown in the dialog.
function confirmDialog({ title, text, confirm, danger = true, action }) {
  const err = h("div", { class: "form-error", role: "alert", hidden: true });
  const ok = h("button", {
    type: "button",
    class: danger ? "danger-solid" : "primary",
    onclick: async () => {
      ok.disabled = true;
      err.hidden = true;
      try {
        await action();
        dlg.close();
      } catch (e) {
        if (isAbort(e)) return;
        err.textContent = e.message;
        err.hidden = false;
        ok.disabled = false;
      }
    },
  }, confirm);
  const cancel = h("button", { type: "button", onclick: () => dlg.close() }, "Abbrechen");
  const dlg = openDialog(title, [h("p", {}, text), err, h("div", { class: "dialog-foot" }, cancel, ok)]);
  cancel.focus();
}

// --- Forms: fields with error slots ----------------------------------------

class FieldError extends Error {
  constructor(key, message) {
    super(message);
    this.key = key;
  }
}

// Collects the fields of one form so 422 "fields" land next to the right input.
// Keys like "upstreams.2" or "safesearch.google" fall back to their first part.
function errorScope(general) {
  const fields = new Map();
  const shown = [];
  const scope = {
    general,
    register(key, entry) { fields.set(key, entry); },
    clear() {
      if (general) general.hidden = true;
      for (const e of shown.splice(0)) {
        e.err.hidden = true;
        e.err.textContent = "";
        for (const i of e.inputs || []) i.removeAttribute("aria-invalid");
      }
    },
    show(error) {
      scope.clear();
      const map = error.fields || {};
      const rest = [];
      let first = null;
      for (const [key, msg] of Object.entries(map)) {
        const parts = key.split(".");
        let entry = null;
        let sub = [];
        for (let n = parts.length; n > 0 && !entry; n--) {
          entry = fields.get(parts.slice(0, n).join("."));
          if (entry) sub = parts.slice(n);
        }
        if (!entry) { rest.push(msg); continue; }
        const text = entry.describe ? entry.describe(sub, msg) : msg;
        entry.err.textContent = entry.err.textContent ? entry.err.textContent + " " + text : text;
        entry.err.hidden = false;
        const marked = entry.inputsFor ? entry.inputsFor(sub) : entry.inputs || [];
        for (const i of marked) i.setAttribute("aria-invalid", "true");
        shown.push({ err: entry.err, inputs: marked });
        if (!first && marked[0]) first = marked[0];
      }
      if (general) {
        const text = rest.length ? rest.join(" ") : Object.keys(map).length ? "" : error.message;
        general.textContent = text || "";
        general.hidden = !text;
        if (text && !first) general.scrollIntoView({ block: "nearest" });
      }
      if (first) first.focus();
    },
  };
  return scope;
}

// Builds label + control + hint + error slot. Returns the wrapper; the control keeps its own id.
function field(scope, key, label, control, opts = {}) {
  const id = control.id || (control.id = nextId("i"));
  const err = h("div", { class: "field-error", id: id + "-err", role: "alert", hidden: true });
  const hint = opts.hint ? h("div", { class: "hint", id: id + "-hint" }, opts.hint) : null;
  control.setAttribute("aria-describedby", [hint && hint.id, err.id].filter(Boolean).join(" "));
  if (scope && key) scope.register(key, { err, inputs: [control], describe: opts.describe });
  // A correction hides the stale message right away.
  control.addEventListener("input", () => {
    if (err.hidden) return;
    err.hidden = true;
    err.textContent = "";
    control.removeAttribute("aria-invalid");
  });
  return h("div", { class: "field" + (opts.class ? " " + opts.class : "") },
    h("label", { for: id }, label), control, hint, err);
}

function toggle(label, checked, opts = {}) {
  const input = h("input", { type: "checkbox", checked: !!checked, class: opts.plain ? "plain" : "", onchange: opts.onchange, disabled: opts.disabled });
  if (opts.hint) {
    const hintId = nextId("th");
    input.setAttribute("aria-describedby", hintId);
    return { input, el: h("label", { class: "check top" }, input, h("span", { class: "check-text" }, h("span", {}, label), h("span", { class: "hint", id: hintId }, opts.hint))) };
  }
  return { input, el: h("label", { class: "check" }, input, h("span", {}, label)) };
}

function numberValue(input, key) {
  const raw = input.value.trim().replace(",", ".");
  const n = Number(raw);
  if (raw === "" || !Number.isFinite(n) || !Number.isInteger(n)) throw new FieldError(key, "Bitte eine ganze Zahl eingeben.");
  return n;
}

// --- Icons and brand -------------------------------------------------------

const logo = () => s("svg", { viewBox: "0 0 16 16", "aria-hidden": "true" },
  s("rect", { width: 16, height: 16, rx: 3.6, fill: "#0071e3" }),
  s("path", { d: "M8 3.2 12 4.7v3c0 2.4-1.6 4.2-4 5-2.4-.8-4-2.6-4-5v-3z", fill: "none", stroke: "#fff", "stroke-width": 1.6, "stroke-linejoin": "round" }));

// Own line icons on a 24 × 24 grid, the page deliberately loads nothing from outside.
const icon = (d) => s("svg", { class: "icon", viewBox: "0 0 24 24", "aria-hidden": "true" }, s("path", { d }));
const ICONS = {
  overview: "M4 4h7v7H4zM13 4h7v7h-7zM4 13h7v7H4zM13 13h7v7h-7z",
  log: "M9 6h11M9 12h11M9 18h11M4.5 6h.01M4.5 12h.01M4.5 18h.01",
  lists: "M12 3l8 3v6c0 4.5-3.2 7.8-8 9-4.8-1.2-8-4.5-8-9V6z",
  rules: "M4 20h4L19 9l-4-4L4 16zM13.5 6.5l4 4",
  rewrites: "M10 14a4 4 0 0 0 5.7 0l3-3a4 4 0 0 0-5.7-5.7l-1 1M14 10a4 4 0 0 0-5.7 0l-3 3a4 4 0 0 0 5.7 5.7l1-1",
  services: "M7 11V8a5 5 0 0 1 10 0v3M6 11h12v9H6zM12 15v1.5",
  clients: "M3 5h13v9H3zM6.5 18h6M9.5 14v4M18 9h3v10h-3z",
  settings: "M4 7h9M17 7h3M4 17h3M11 17h9M15 5v4M9 15v4",
  logout: "M15 4h4v16h-4M10 8l-4 4 4 4M6 12h9",
  menu: "M4 7h16M4 12h16M4 17h16",
  refresh: "M20 11a8 8 0 0 0-14.3-4L4 9M4 4v5h5M4 13a8 8 0 0 0 14.3 4L20 15M20 20v-5h-5",
  edit: "M4 20h4L19 9l-4-4L4 16z",
  trash: "M4 7h16M10 11v6M14 11v6M6 7l1 13h10l1-13M9 7V4h6v3",
  plus: "M12 5v14M5 12h14",
  chevron: "M6 9l6 6 6-6",
  pause: "M9 5v14M15 5v14",
  shieldCheck: "M12 3l8 3v6c0 4.5-3.2 7.8-8 9-4.8-1.2-8-4.5-8-9V6zM8.5 12l2.5 2.5 4.5-5",
  shieldOff: "M12 3l8 3v6c0 4.5-3.2 7.8-8 9-4.8-1.2-8-4.5-8-9V6zM9 9l6 6M15 9l-6 6",
  warn: "M12 4 3 20h18zM12 10v4.5M12 17.5h.01",
  info: "M12 21a9 9 0 1 0 0-18 9 9 0 0 0 0 18zM12 11v5M12 8h.01",
};

function banner(kind, title, text, extra) {
  return h("div", { class: "banner " + (kind || ""), role: kind === "error" ? "alert" : "status" },
    icon(kind === "info" ? ICONS.info : ICONS.warn),
    h("div", { class: "banner-text" }, title ? h("strong", {}, title) : null, text ? h("span", {}, text) : null, extra || null));
}

// --- Shared vocabulary -----------------------------------------------------

const STATUS = {
  ok: ["OK", ""],
  allowed: ["Erlaubt", "good"],
  blocked: ["Blockiert", "bad"],
  blocked_service: ["Dienst blockiert", "bad"],
  safesearch: ["SafeSearch", "info"],
  rewrite: ["Umgeschrieben", "info"],
  refused: ["Abgewiesen", "warn"],
  error: ["Fehler", "warn"],
};

const REASONS = {
  list: "Liste",
  custom: "Eigene Regel",
  service: "Dienst",
  safesearch: "SafeSearch",
  rewrite: "Lokaler Eintrag",
  access: "Client nicht zugelassen",
  any: "ANY-Anfrage abgelehnt",
  ratelimit: "Ratenlimit überschritten",
  upstream: "Kein Upstream erreichbar",
};

function statusBadge(status, cached) {
  const [label, cls] = STATUS[status] || [status || "?", ""];
  return h("span", { class: "badge " + cls }, cached && status === "ok" ? "Aus dem Cache" : label);
}

const SERVICE_GROUPS = [
  ["social", "Soziale Netzwerke"],
  ["messenger", "Messenger"],
  ["video", "Video & Streaming"],
  ["music", "Musik"],
  ["gaming", "Spiele"],
  ["shopping", "Shopping"],
  ["ai", "KI"],
  ["other", "Sonstiges"],
];

const ENGINES = [["google", "Google"], ["bing", "Bing"], ["duckduckgo", "DuckDuckGo"], ["youtube", "YouTube"], ["yandex", "Yandex"], ["pixabay", "Pixabay"]];

// The service catalog never changes while the server runs; one request per page load is enough.
let servicesPromise = null;
function loadServiceCatalog() {
  if (!servicesPromise) {
    servicesPromise = api("services").then((d) => d, (e) => { servicesPromise = null; throw e; });
  }
  return servicesPromise;
}

function serviceName(catalog, id) {
  const found = catalog && catalog.services.find((x) => x.id === id);
  return found ? found.name : id;
}

// Human readable explanation of a log entry or check result.
function decisionDetail(x, catalog) {
  const parts = [];
  if (x.status === "blocked_service" || x.reason === "service") {
    if (x.service) parts.push(serviceName(catalog, x.service));
  } else if (x.reason === "list") {
    if (x.list_name) parts.push(x.list_name);
  } else if (x.reason && REASONS[x.reason] && !(x.status === "rewrite" && x.reason === "rewrite" && x.rule)) {
    parts.push(REASONS[x.reason]);
  }
  return parts.join(" · ");
}

// --- Shell, routing and session --------------------------------------------

const NAV = [
  ["overview", "Übersicht"],
  ["log", "Abfragen"],
  ["lists", "Blocklisten"],
  ["rules", "Eigene Regeln"],
  ["rewrites", "Lokale Einträge"],
  ["services", "Dienste"],
  ["clients", "Clients"],
  ["settings", "Einstellungen"],
];

let me = null;
let mainEl = null;
let navLinks = {};
let current = null;
let menuButton = null;
let sideState = null;
let versionEl = null;

function parseHash() {
  const raw = location.hash.replace(/^#\/?/, "");
  const [name, query] = raw.split("?");
  return { name: name || "overview", params: new URLSearchParams(query || "") };
}

function setHashParams(name, params) {
  const q = params.toString();
  history.replaceState(null, "", "#/" + name + (q ? "?" + q : ""));
}

// One context per rendered page: aborts its requests and stops its timers when the page goes.
function makeContext() {
  const ac = new AbortController();
  const fns = [];
  const ctx = {
    signal: ac.signal,
    get dead() { return ac.signal.aborted; },
    on(fn) { fns.push(fn); },
    api(path, opts = {}) { return api(path, { ...opts, signal: ac.signal }); },
    dispose() {
      ac.abort();
      for (const fn of fns.splice(0)) { try { fn(); } catch { /* ignore */ } }
    },
    // Runs fn now and then every ms while the tab is visible. Calls never overlap.
    poll(fn, ms) {
      let t = null;
      let busy = false;
      let again = false;
      let on = true;
      const tick = async () => {
        clearTimeout(t);
        t = null;
        if (ctx.dead || !on) return;
        if (busy) { again = true; return; }
        busy = true;
        try { if (!document.hidden) await fn(); } catch (e) { if (!isAbort(e)) console.warn(e); }
        busy = false;
        if (ctx.dead || !on) return;
        if (again) { again = false; tick(); return; }
        t = setTimeout(tick, ms);
      };
      const vis = () => { if (!document.hidden) tick(); };
      document.addEventListener("visibilitychange", vis);
      ctx.on(() => { clearTimeout(t); document.removeEventListener("visibilitychange", vis); });
      return {
        now: tick,
        set(enabled) {
          on = enabled;
          if (on) tick(); else { clearTimeout(t); t = null; }
        },
      };
    },
  };
  return ctx;
}

function openMenu() {
  document.body.classList.add("menu-open");
  menuButton.setAttribute("aria-expanded", "true");
  const cur = document.querySelector('.sidebar a[aria-current="page"]');
  if (cur) cur.focus();
}

function closeMenu() {
  if (!document.body.classList.contains("menu-open")) return;
  document.body.classList.remove("menu-open");
  if (menuButton) {
    menuButton.setAttribute("aria-expanded", "false");
    if (window.matchMedia("(max-width: 900px)").matches) menuButton.focus();
  }
}

window.addEventListener("keydown", (e) => { if (e.key === "Escape") closeMenu(); });

const THEMES = [["light", "Hell"], ["dark", "Dunkel"], ["auto", "Auto"]];

// "Auto" follows the system. The choice is stored per browser.
function themeSwitch() {
  const cur = () => document.documentElement.getAttribute("data-theme") || "auto";
  const buttons = THEMES.map(([id, label]) => h("button", {
    type: "button",
    "aria-pressed": String(cur() === id),
    title: id === "auto" ? "Wie im Betriebssystem eingestellt" : `Immer ${label.toLowerCase()}`,
    onclick: () => {
      if (id === "auto") document.documentElement.removeAttribute("data-theme");
      else document.documentElement.setAttribute("data-theme", id);
      try {
        if (id === "auto") localStorage.removeItem("pk95dns-theme");
        else localStorage.setItem("pk95dns-theme", id);
      } catch { /* then it only lasts until reload */ }
      buttons.forEach((b, i) => b.setAttribute("aria-pressed", String(THEMES[i][0] === id)));
    },
  }, label));
  return h("div", { class: "segmented theme-switch", role: "group", "aria-label": "Darstellung" }, buttons);
}

function protectionState(p) {
  if (!p) return "on";
  if (p.paused_until > Date.now()) return "paused";
  return p.enabled ? "on" : "off";
}

// Small protection indicator in the sidebar, fed by every /api/status the app loads.
function updateSideStatus(status) {
  if (!status) return;
  if (versionEl) versionEl.textContent = "PK95 DNS " + (status.version || "");
  if (!sideState) return;
  const st = protectionState(status.protection);
  const text = { on: "Schutz aktiv", paused: "Schutz pausiert", off: "Schutz aus" }[st];
  const cls = { on: "good", paused: "warn", off: "bad" }[st];
  const dnsDown = status.dns && status.dns.error;
  sideState.replaceChildren(h("span", { class: "dot " + (dnsDown ? "bad" : cls) }), dnsDown ? "DNS-Server gestört" : text);
}

function renderShell() {
  navLinks = {};
  mainEl = h("main", { id: "main", tabindex: -1 });
  document.body.classList.remove("menu-open");
  menuButton = h("button", { class: "menu-button", type: "button", "aria-label": "Menü öffnen", "aria-expanded": "false", "aria-controls": "sidebar", onclick: openMenu }, icon(ICONS.menu));
  sideState = h("div", { class: "side-state" });
  versionEl = h("div", { class: "side-meta small muted" }, "PK95 DNS");
  app.replaceChildren(h("div", { class: "shell" },
    h("aside", { class: "sidebar", id: "sidebar" },
      h("div", { class: "brand" }, logo(), "PK95 DNS"),
      h("nav", { class: "nav", "aria-label": "Hauptnavigation" },
        NAV.map(([id, label]) => (navLinks[id] = h("a", { href: "#/" + id, onclick: closeMenu }, icon(ICONS[id]), label)))),
      h("div", { class: "side-foot" },
        sideState,
        themeSwitch(),
        versionEl,
        h("div", { class: "side-meta small muted", title: "Angemeldet als" }, me.username),
        h("button", { class: "side-link", type: "button", onclick: logout }, icon(ICONS.logout), "Abmelden"))),
    h("div", { class: "scrim", onclick: closeMenu }),
    h("div", { class: "content" },
      h("header", { class: "mobilebar" }, menuButton, h("div", { class: "brand" }, logo(), "PK95 DNS")),
      mainEl)));
  api("status").then(updateSideStatus, () => { /* the overview shows errors */ });
}

const VIEWS = {};

function route() {
  if (!me) return;
  document.body.classList.remove("menu-open");
  if (current) { current.dispose(); current = null; }
  const { name, params } = parseHash();
  const key = VIEWS[name] ? name : "overview";
  for (const [id, link] of Object.entries(navLinks)) {
    if (id === key) link.setAttribute("aria-current", "page");
    else link.removeAttribute("aria-current");
  }
  const label = (NAV.find(([id]) => id === key) || [])[1];
  document.title = label ? `${label} – PK95 DNS` : "PK95 DNS";
  mainEl.replaceChildren();
  const container = h("div");
  mainEl.append(container);
  current = makeContext();
  VIEWS[key](container, params, current);
}

window.addEventListener("hashchange", route);

async function logout() {
  try { await api("logout", { method: "POST", noAuthRedirect: true }); } catch { /* signed out anyway */ }
  showLogin();
}

// Several requests may fail with 401 at once; only the first one switches to the login form.
function onUnauthorized() {
  if (!me) return;
  showLogin("Deine Sitzung ist abgelaufen. Bitte melde dich neu an.");
}

function showCoreNote(message) {
  me = null;
  document.title = "PK95 DNS";
  app.replaceChildren(h("div", { class: "login" },
    h("div", { class: "login-box" },
      h("div", { class: "brand" }, logo(), h("h1", {}, "PK95 DNS")),
      h("p", { class: "login-note" }, message || "PK95 DNS wird über PK95 Core verwaltet."),
      h("p", { class: "login-note small" }, "Öffne PK95 Core, um Filter, Listen und Einstellungen zu bearbeiten."))));
}

function showLogin(note) {
  me = null;
  document.body.classList.remove("menu-open");
  if (current) { current.dispose(); current = null; }
  document.querySelectorAll("dialog").forEach((d) => d.remove());
  document.title = "Anmelden – PK95 DNS";
  const err = h("div", { class: "form-error", role: "alert", hidden: !note }, note || "");
  const user = h("input", { type: "text", id: "lu", autocomplete: "username", value: "admin", required: true, autocapitalize: "none", spellcheck: false });
  const pass = h("input", { type: "password", id: "lp", autocomplete: "current-password", required: true });
  const submit = h("button", { class: "primary", type: "submit" }, "Anmelden");
  const form = h("form", {
    class: "login-box",
    onsubmit: async (e) => {
      e.preventDefault();
      err.hidden = true;
      submit.disabled = true;
      try {
        await api("login", { method: "POST", body: { username: user.value.trim(), password: pass.value }, noAuthRedirect: true });
        await start();
        return;
      } catch (ex) {
        if (ex.status === 401 && /core/i.test(ex.message)) { showCoreNote(ex.message); return; }
        if (ex.status === 429) err.textContent = ex.message || "Zu viele Fehlversuche. Bitte warte 15 Minuten und versuche es dann erneut.";
        else if (ex.status === 401) err.textContent = ex.message || "Benutzername oder Passwort stimmen nicht.";
        else err.textContent = ex.message;
        err.hidden = false;
        submit.disabled = false;
        pass.select();
        pass.focus();
      }
    },
  },
    h("div", { class: "brand" }, logo(), h("h1", {}, "PK95 DNS")),
    err,
    h("div", { class: "field" }, h("label", { for: "lu" }, "Benutzername"), user),
    h("div", { class: "field" }, h("label", { for: "lp" }, "Passwort"), pass),
    submit,
    h("p", { class: "hint", style: "text-align:center" }, "Beim ersten Start steht das Passwort in der Datei initial-admin-password im Datenordner."));
  app.replaceChildren(h("div", { class: "login" }, form));
  pass.focus();
}

async function start() {
  try {
    me = await api("me", { noAuthRedirect: true });
  } catch (e) {
    if (e.status === 401) showLogin();
    else {
      app.replaceChildren(h("div", { class: "login" }, h("div", { class: "login-box" },
        h("div", { class: "brand" }, logo(), h("h1", {}, "PK95 DNS")),
        h("div", { class: "form-error", role: "alert" }, e.message),
        h("button", { class: "primary", type: "button", onclick: start }, "Erneut versuchen"))));
    }
    return;
  }
  if (me.core_mode) { showCoreNote(); return; }
  renderShell();
  route();
}

// --- Chart helpers ---------------------------------------------------------

function niceStep(max, ticks) {
  if (max <= 0) return 1;
  const raw = max / ticks;
  const pow = Math.pow(10, Math.floor(Math.log10(raw)));
  const n = raw / pow;
  const nice = n <= 1 ? 1 : n <= 2 ? 2 : n <= 5 ? 5 : 10;
  return Math.max(1, nice * pow);
}

function roundedBar(x, yTop, w, yBottom, r) {
  r = Math.max(0, Math.min(r, w / 2, yBottom - yTop));
  return `M${x},${yBottom}V${yTop + r}Q${x},${yTop} ${x + r},${yTop}H${x + w - r}Q${x + w},${yTop} ${x + w},${yTop + r}V${yBottom}Z`;
}

// --- Übersicht -------------------------------------------------------------

const RANGES = [["24", "24 Std."], ["168", "7 Tage"], ["720", "30 Tage"]];
const PAUSES = [[1, "1 Minute"], [10, "10 Minuten"], [60, "1 Stunde"], [480, "8 Stunden"], [1440, "24 Stunden"], [0, "Bis ich es einschalte"]];

// A small accessible popover menu (button + list of actions).
function popoverMenu(label, title, items, onPick) {
  const btn = h("button", { type: "button", "aria-haspopup": "menu", "aria-expanded": "false" }, icon(ICONS.pause), label, icon(ICONS.chevron));
  const menu = h("div", { class: "menu", role: "menu", hidden: true, "aria-label": title });
  const wrap = h("div", { class: "menu-wrap" }, btn, menu);
  const buttons = items.map(([value, text]) => h("button", {
    type: "button", role: "menuitem", tabindex: -1,
    onclick: () => { close(true); onPick(value); },
  }, text));
  append(menu, [h("div", { class: "menu-label", "aria-hidden": "true" }, title), buttons]);
  const outside = (e) => { if (!wrap.contains(e.target)) close(false); };
  function open() {
    menu.hidden = false;
    btn.setAttribute("aria-expanded", "true");
    buttons[0].focus();
    document.addEventListener("pointerdown", outside, true);
  }
  function close(focusButton) {
    if (menu.hidden) return;
    menu.hidden = true;
    btn.setAttribute("aria-expanded", "false");
    document.removeEventListener("pointerdown", outside, true);
    if (focusButton) btn.focus();
  }
  btn.addEventListener("click", () => (menu.hidden ? open() : close(true)));
  btn.addEventListener("keydown", (e) => { if (e.key === "ArrowDown") { e.preventDefault(); open(); } });
  menu.addEventListener("keydown", (e) => {
    const i = buttons.indexOf(document.activeElement);
    if (e.key === "ArrowDown") { e.preventDefault(); buttons[(i + 1) % buttons.length].focus(); }
    else if (e.key === "ArrowUp") { e.preventDefault(); buttons[(i - 1 + buttons.length) % buttons.length].focus(); }
    else if (e.key === "Home") { e.preventDefault(); buttons[0].focus(); }
    else if (e.key === "End") { e.preventDefault(); buttons[buttons.length - 1].focus(); }
    else if (e.key === "Escape") { e.preventDefault(); e.stopPropagation(); close(true); }
    else if (e.key === "Tab") close(false);
  });
  return { el: wrap, close: () => close(false) };
}

VIEWS.overview = function viewOverview(root, params, ctx) {
  let range = params.get("range") || "24";
  if (!RANGES.some(([id]) => id === range)) range = "24";
  let status = null;
  let stats = null;
  let countdown = null;
  let ro = null;
  let protectionSig = "";
  ctx.on(() => { if (ro) ro.disconnect(); });

  const banners = h("div");
  const protectBox = h("section", { class: "card protect", "aria-label": "Schutz" });
  const statsBox = h("div");
  const stamp = h("span", { class: "small muted", "aria-live": "off" });
  const rangeButtons = RANGES.map(([id, label]) => h("button", {
    type: "button",
    "aria-pressed": String(id === range),
    onclick: () => {
      range = id;
      rangeButtons.forEach((b, i) => b.setAttribute("aria-pressed", String(RANGES[i][0] === id)));
      const p = new URLSearchParams();
      if (range !== "24") p.set("range", range);
      setHashParams("overview", p);
      loadStats();
    },
  }, label));

  root.append(
    h("div", { class: "page-head" }, h("h1", {}, "Übersicht"), stamp),
    banners, protectBox,
    h("div", { class: "filters" }, h("div", { class: "segmented", role: "group", "aria-label": "Zeitraum" }, rangeButtons)),
    statsBox);
  ctx.on(() => clearInterval(countdown));

  async function loadStatus() {
    status = await ctx.api("status");
    updateSideStatus(status);
    renderBanners();
    renderProtection();
  }

  async function loadStats() {
    statsBox.classList.add("loading");
    try {
      stats = await ctx.api("stats?hours=" + range);
      renderStats();
      stamp.textContent = "Stand " + fmtTime.format(new Date());
    } catch (e) {
      if (isAbort(e)) return;
      statsBox.replaceChildren(banner("error", "Die Statistik konnte nicht geladen werden.", e.message));
    } finally {
      statsBox.classList.remove("loading");
    }
  }

  const poller = ctx.poll(async () => {
    try {
      await Promise.all([loadStatus(), loadStats()]);
    } catch (e) {
      if (isAbort(e) || e.status === 401) return;
      banners.replaceChildren(banner("error", "PK95 DNS antwortet nicht.", e.message));
    }
  }, 10000);

  function renderBanners() {
    const out = [];
    if (status.dns && status.dns.error) {
      out.push(banner("error", "Der DNS-Server läuft nicht.",
        `${status.dns.error} PK95 DNS versucht es alle 30 Sekunden erneut. Oft belegt ein anderer Dienst (zum Beispiel systemd-resolved) den Port 53.`));
    }
    const ups = status.upstreams || [];
    const failing = ups.filter((u) => !u.ok && (u.queries > 0 || u.last_error));
    if (ups.length && failing.length === ups.length) {
      out.push(banner("error", "Kein Upstream-DNS antwortet.",
        "Anfragen, die nicht aus dem Cache kommen, schlagen fehl. Prüfe die Internetverbindung und die Upstream-Server.",
        h("a", { href: "#/settings" }, "Zu den Einstellungen")));
    } else if (failing.length) {
      out.push(banner("", failing.length === 1 ? "Ein Upstream-DNS antwortet nicht." : `${failing.length} Upstream-DNS antworten nicht.`, null,
        h("span", { class: "small" }, failing.map((u) => `${u.address}${u.last_error ? ": " + u.last_error : ""}`).join(" · "))));
    }
    banners.replaceChildren(...out);
  }

  async function setProtection(body, okText) {
    try {
      const p = await ctx.api("protection", { method: "POST", body });
      status.protection = p;
      renderProtection();
      updateSideStatus(status);
      toast(okText);
    } catch (e) {
      toastError(e);
    }
  }

  // Re-rendered only when something changed, so an open pause menu survives the 10 s refresh.
  function renderProtection() {
    const p = status.protection || { enabled: true, paused_until: 0 };
    const st = protectionState(p);
    const sig = JSON.stringify([p, st, status.rules]);
    if (sig === protectionSig) return;
    protectionSig = sig;
    clearInterval(countdown);
    const sub = h("div", { class: "protect-sub" });
    const updateSub = () => {
      if (st === "on") sub.textContent = "Werbung, Tracker und gesperrte Dienste werden blockiert.";
      else if (st === "off") sub.textContent = "Alle Anfragen werden ungefiltert beantwortet. Lokale Einträge gelten weiter.";
      else {
        const left = p.paused_until - Date.now();
        if (left <= 0) { clearInterval(countdown); loadStatus().catch(() => {}); return; }
        sub.replaceChildren("Schaltet sich wieder ein in ", h("span", { class: "countdown" }, fmtRemaining(left)),
          ` (um ${fmtTime.format(new Date(p.paused_until))} Uhr).`);
      }
    };
    updateSub();
    if (st === "paused") countdown = setInterval(updateSub, 1000);

    const r = status.rules || {};
    const facts = [
      `${plural(r.list_rules || 0, "Regel", "Regeln")} aus ${plural(r.lists || 0, "Liste", "Listen")}`,
      plural(r.custom_rules || 0, "eigene Regel", "eigene Regeln"),
      plural(r.rewrites || 0, "lokaler Eintrag", "lokale Einträge"),
      plural(r.services || 0, "Dienst gesperrt", "Dienste gesperrt"),
    ];

    const sw = h("button", {
      type: "button", role: "switch", class: "big-switch" + (st === "paused" ? " paused" : ""),
      "aria-checked": String(st === "on"), "aria-label": "Schutz",
      title: st === "on" ? "Schutz ausschalten" : "Schutz einschalten",
      onclick: () => (st === "on"
        ? setProtection({ enabled: false, minutes: 0 }, "Schutz ist aus, bis du ihn wieder einschaltest.")
        : setProtection({ enabled: true }, "Schutz ist wieder aktiv.")),
    });
    const menu = popoverMenu(st === "paused" ? "Pause ändern" : "Pausieren", "Schutz pausieren für", PAUSES, (minutes) => {
      if (minutes === 0) setProtection({ enabled: false, minutes: 0 }, "Schutz ist aus, bis du ihn wieder einschaltest.");
      else setProtection({ enabled: false, minutes }, `Schutz pausiert für ${PAUSES.find(([m]) => m === minutes)[1]}.`);
    });
    const title = { on: "Schutz ist aktiv", paused: "Schutz ist pausiert", off: "Schutz ist aus" }[st];
    protectBox.replaceChildren(
      h("div", { class: "protect-main" },
        h("div", { class: "shield" + (st === "on" ? "" : " " + st) }, icon(st === "on" ? ICONS.shieldCheck : ICONS.shieldOff)),
        h("div", { class: "protect-text" },
          h("div", { class: "protect-title" }, title), sub,
          h("div", { class: "rule-facts" }, facts.join(" · ")))),
      h("div", { class: "protect-actions" }, st === "off" ? null : menu.el, sw));
  }

  function tile(label, value, sub, cls) {
    return h("div", { class: "card tile" + (cls ? " " + cls : "") },
      h("div", { class: "label" }, label),
      h("div", { class: "value" }, value),
      h("div", { class: "sub" }, sub));
  }

  function renderStats() {
    const t = stats.totals || {};
    const rangeText = { 24: "in den letzten 24 Std.", 168: "in den letzten 7 Tagen", 720: "in den letzten 30 Tagen" }[range];
    const blockedSub = [`${fmtPct(t.blocked_pct || pct(t.blocked, t.queries))} aller Anfragen`];
    if (t.services) blockedSub.push(`${nf.format(t.services)} durch Dienste`);
    const chartBox = h("div", { class: "chart" });
    statsBox.replaceChildren(
      h("div", { class: "tiles" },
        tile("Anfragen", fmtCompact(t.queries), rangeText),
        tile("Blockiert", fmtCompact(t.blocked), blockedSub.join(", "), "blocked"),
        tile("Aus dem Cache", fmtCompact(t.cached), `${fmtPct(pct(t.cached, t.queries))} aller Anfragen`),
        tile("Ø Antwortzeit", fmtMs(t.avg_ms || 0), t.safesearch ? `${nf.format(t.safesearch)} × SafeSearch` : "über alle Anfragen")),
      h("section", { class: "card" },
        h("div", { class: "chart-head" },
          h("h2", {}, "Anfragen im Zeitverlauf"),
          h("div", { class: "legend" },
            h("span", {}, h("i", { class: "swatch queries" }), "Anfragen"),
            h("span", {}, h("i", { class: "swatch blocked" }), "davon blockiert"))),
        chartBox),
      h("div", { class: "grid-top" },
        topCard("Häufigste Domains", stats.top_domains, (x) => ({ label: x.name, href: logHref({ search: x.name }) })),
        topCard("Blockierte Domains", stats.top_blocked, (x) => ({ label: x.name, href: logHref({ search: x.name, status: "blocked" }), blocked: true })),
        topCard("Clients", stats.top_clients, (x) => ({
          label: x.name || x.ip, extra: x.name ? x.ip : null, href: logHref({ client: x.ip }),
          title: `${x.name ? x.name + " – " : ""}${x.ip}: ${nf.format(x.count)} Anfragen, ${nf.format(x.blocked || 0)} blockiert`,
        })),
        topCard("Upstreams", stats.top_upstreams, (x) => ({ label: x.address, extra: x.avg_ms ? "Ø " + fmtMs(x.avg_ms) : null }))));
    drawChart(chartBox);
    if (ro) ro.disconnect();
    if ("ResizeObserver" in window) {
      let w = chartBox.clientWidth;
      ro = new ResizeObserver(() => {
        if (Math.abs(chartBox.clientWidth - w) > 4) { w = chartBox.clientWidth; drawChart(chartBox); }
      });
      ro.observe(chartBox);
    }
  }

  function logHref(p) {
    const q = new URLSearchParams();
    for (const [k, v] of Object.entries(p)) if (v) q.set(k, v);
    return "#/log?" + q;
  }

  function topCard(title, items, describe) {
    items = items || [];
    const max = items.reduce((m, i) => Math.max(m, i.count), 0);
    const list = h("ol", { class: "top-list" }, items.map((it) => {
      const d = describe(it);
      const nameEl = d.href ? h("a", { href: d.href, title: d.title || d.label }, d.label) : h("span", { title: d.title || d.label }, d.label);
      const bar = h("div", { class: "bar" + (d.blocked ? " blocked" : "") });
      bar.style.width = (max ? (it.count / max) * 100 : 0) + "%";
      return h("li", { class: "top-row" },
        h("div", { class: "line" },
          h("div", { class: "name" }, nameEl, d.extra ? h("span", { class: "muted small" }, d.extra) : null),
          h("span", { class: "count" }, nf.format(it.count))),
        h("div", { class: "track", "aria-hidden": "true" }, bar));
    }));
    return h("section", { class: "card" }, h("h2", {}, title), items.length ? list : h("p", { class: "empty" }, "Noch keine Daten"));
  }

  function bucketLabel(ts) {
    const d = new Date(ts);
    if (stats.granularity === "day") return fmtDayLong.format(d);
    const end = new Date(ts + 3600000);
    return `${fmtWeekday.format(d)}, ${fmtTime.format(d)}–${fmtTime.format(end)} Uhr`;
  }

  function drawChart(box) {
    const series = stats.series || [];
    const total = series.reduce((sum, b) => sum + b.queries, 0);
    if (!series.length || total === 0) {
      box.replaceChildren(h("div", { class: "chart-empty" }, "In diesem Zeitraum gab es noch keine Anfragen."));
      return;
    }
    const width = Math.max(box.clientWidth, 260);
    const height = 220;
    const m = { top: 10, right: 4, bottom: 24, left: 52 };
    const plotW = width - m.left - m.right;
    const plotH = height - m.top - m.bottom;
    const maxVal = series.reduce((mx, b) => Math.max(mx, b.queries), 0);
    const step = niceStep(maxVal, 4);
    const top = Math.max(step, Math.ceil(maxVal / step) * step);
    const y = (v) => m.top + plotH - (v / top) * plotH;
    const slot = plotW / series.length;
    const barW = Math.min(18, Math.max(1.5, slot - (slot > 6 ? 2 : 0.6)));
    const svg = s("svg", {
      viewBox: `0 0 ${width} ${height}`, height, role: "img",
      "aria-label": `Anfragen im Zeitverlauf: ${nf.format(total)} Anfragen, davon ${nf.format(series.reduce((x, b) => x + b.blocked, 0))} blockiert`,
    });
    for (let v = 0; v <= top; v += step) {
      svg.append(s("line", { class: v === 0 ? "baseline" : "gridline", x1: m.left, x2: width - m.right, y1: y(v) + 0.5, y2: y(v) + 0.5 }));
      svg.append(s("text", { x: m.left - 8, y: y(v) + 4, "text-anchor": "end" }, fmtAxis(v)));
    }
    const tip = h("div", { class: "tooltip", hidden: true });
    const maxLabels = Math.max(2, Math.floor(plotW / 64));
    const labelEvery = Math.max(1, Math.ceil(series.length / maxLabels));
    const dayMarks = stats.granularity !== "day" && series.length > 30;
    const dayEvery = Math.max(1, Math.ceil(7 / Math.max(1, Math.floor(plotW / 64))));
    let dayCount = 0;
    series.forEach((b, i) => {
      const d = new Date(b.t);
      const cx = m.left + slot * i + slot / 2;
      if (dayMarks) {
        if (d.getHours() === 0) {
          if (dayCount++ % dayEvery === 0) svg.append(s("text", { x: cx, y: height - 6, "text-anchor": "middle" }, fmtWeekday.format(d)));
        }
      } else if (i % labelEvery === 0) {
        svg.append(s("text", { x: cx, y: height - 6, "text-anchor": "middle" }, stats.granularity === "day" ? fmtDay.format(d) : fmtTime.format(d)));
      }
      const band = s("rect", { class: "band", x: m.left + slot * i, y: m.top, width: slot, height: plotH + 1 });
      const show = () => {
        band.setAttribute("class", "band on");
        tip.replaceChildren(
          h("div", { class: "when" }, bucketLabel(b.t)),
          h("div", { class: "row" }, h("i", { class: "swatch queries" }), h("b", {}, nf.format(b.queries)), h("span", {}, "Anfragen")),
          h("div", { class: "row" }, h("i", { class: "swatch blocked" }), h("b", {}, nf.format(b.blocked)),
            h("span", {}, `blockiert (${fmtPct(pct(b.blocked, b.queries))})`)));
        tip.hidden = false;
        let left = cx + 14;
        if (left + tip.offsetWidth > width) left = cx - tip.offsetWidth - 14;
        tip.style.transform = `translate(${Math.max(0, left)}px, ${m.top}px)`;
      };
      band.addEventListener("pointerenter", show);
      band.addEventListener("pointermove", show);
      band.addEventListener("pointerleave", () => { band.setAttribute("class", "band"); tip.hidden = true; });
      svg.append(band);
      const x = m.left + slot * i + (slot - barW) / 2;
      const yBottom = m.top + plotH;
      if (b.queries > 0) {
        const yq = Math.min(y(b.queries), yBottom - 1);
        svg.append(s("path", { class: "fill-queries", "pointer-events": "none", d: roundedBar(x, yq, barW, yBottom, 3) }));
      }
      if (b.blocked > 0) {
        const yb = Math.min(y(b.blocked), yBottom - 1);
        const r = b.blocked >= b.queries ? 3 : 0;
        svg.append(s("path", { class: "fill-blocked", "pointer-events": "none", d: roundedBar(x, yb, barW, yBottom, r) }));
      }
    });
    svg.addEventListener("pointerleave", () => { tip.hidden = true; });
    box.replaceChildren(svg, tip);
  }

  poller.now();
};

// --- Abfragen (query log) --------------------------------------------------

const LOG_STATUS = [["all", "Alle Status"], ["blocked", "Blockiert"], ["allowed", "Erlaubt"], ["rewritten", "Umgeschrieben"], ["failed", "Fehler und abgewiesen"]];

// Sends a quick block/allow rule for exactly this domain and reports the result.
// Names the API accepts for quick rules (filter.ValidDomain): root queries ("") and names
// with spaces or escapes get no quick action.
const QUICKABLE = /^(?=.{1,253}$)[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?(?:\.[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?)*$/;

async function quickRule(domain, action, signal) {
  const res = await api("rules/quick", { method: "POST", body: { domain, action }, signal });
  const text = {
    block: `„${domain}“ wird ab jetzt blockiert.`,
    allow: `„${domain}“ ist jetzt freigegeben.`,
    remove: `Eigene Regeln für „${domain}“ entfernt.`,
  }[action];
  toast(text);
  return res;
}

function debounce(fn, ms) {
  let t = null;
  return (...args) => { clearTimeout(t); t = setTimeout(() => fn(...args), ms); };
}

VIEWS.log = function viewLog(root, params, ctx) {
  const state = {
    search: params.get("search") || "",
    client: params.get("client") || "",
    status: LOG_STATUS.some(([id]) => id === params.get("status")) ? params.get("status") : "all",
  };
  let items = [];
  let nextBefore = 0;
  let newestId = 0;
  let catalog = null;
  loadServiceCatalog().then((c) => { catalog = c; }, () => {});

  const search = h("input", { type: "search", placeholder: "Domain suchen", value: state.search, "aria-label": "Domain suchen", spellcheck: false });
  const client = h("input", { type: "text", placeholder: "Client (IP oder Name)", value: state.client, "aria-label": "Client", spellcheck: false, autocapitalize: "none" });
  const statusSel = h("select", { "aria-label": "Status" }, LOG_STATUS.map(([id, label]) => h("option", { value: id }, label)));
  statusSel.value = state.status;
  let autoOn = false;
  try { autoOn = localStorage.getItem("pk95dns-log-live") === "1"; } catch { /* optional */ }
  const auto = toggle("Automatisch aktualisieren", autoOn, {
    onchange: () => {
      try { localStorage.setItem("pk95dns-log-live", auto.input.checked ? "1" : "0"); } catch { /* optional */ }
      live.set(auto.input.checked);
    },
  });
  const tbody = h("tbody");
  const table = h("table", { class: "log-table" },
    h("thead", {}, h("tr", {},
      h("th", { scope: "col" }, "Zeit"), h("th", { scope: "col" }, "Client"), h("th", { scope: "col" }, "Domain"),
      h("th", { scope: "col" }, "Status"), h("th", { scope: "col" }, "Antwort"), h("th", { scope: "col", class: "num" }, "Dauer"),
      h("th", { scope: "col" }, "Upstream"), h("th", { scope: "col" }, h("span", { class: "sr-only" }, "Aktionen")))),
    tbody);
  const emptyBox = h("div", { class: "empty-state", hidden: true });
  const more = h("button", { type: "button", onclick: () => load(true) }, "Mehr laden");
  const errorBox = h("div");
  const noteBox = h("div");

  root.append(
    h("div", { class: "page-head" }, h("h1", {}, "Abfragen"),
      h("div", { class: "actions" },
        h("button", { type: "button", onclick: () => load(false) }, icon(ICONS.refresh), "Aktualisieren"),
        h("button", { type: "button", class: "danger", onclick: clearLog }, icon(ICONS.trash), "Protokoll leeren"))),
    noteBox,
    h("div", { class: "filters" }, search, client, statusSel, h("span", { class: "spacer" }), auto.el),
    errorBox,
    h("div", { class: "table-wrap" }, table, emptyBox, h("div", { class: "log-foot" }, more)));

  ctx.api("settings").then((st) => {
    if (st && st.querylog_enabled === false) {
      noteBox.replaceChildren(banner("info", "Das Abfrageprotokoll ist ausgeschaltet.", "Neue Anfragen werden nicht gespeichert. ", h("a", { href: "#/settings" }, "In den Einstellungen einschalten")));
    }
  }, () => {});

  function syncUrl() {
    const p = new URLSearchParams();
    if (state.search) p.set("search", state.search);
    if (state.client) p.set("client", state.client);
    if (state.status !== "all") p.set("status", state.status);
    setHashParams("log", p);
  }

  const changed = () => {
    state.search = search.value.trim();
    state.client = client.value.trim();
    state.status = statusSel.value;
    syncUrl();
    load(false);
  };
  const changedSoon = debounce(changed, 350);
  search.addEventListener("input", changedSoon);
  client.addEventListener("input", changedSoon);
  statusSel.addEventListener("change", changed);

  // append = next page; otherwise the first page is (re)loaded, and auto refresh keeps as many
  // rows as are on screen so "Mehr laden" pages do not vanish.
  async function load(appendPage, keepCount) {
    const limit = appendPage ? 50 : Math.min(500, Math.max(50, keepCount ? items.length : 50));
    const q = new URLSearchParams({ limit: String(limit), status: state.status });
    if (state.search) q.set("search", state.search);
    if (state.client) q.set("client", state.client);
    if (appendPage && nextBefore) q.set("before", String(nextBefore));
    more.disabled = true;
    try {
      const data = await ctx.api("querylog?" + q);
      const prevNewest = newestId;
      if (appendPage) items = items.concat(data.items || []);
      else items = data.items || [];
      nextBefore = data.next_before || 0;
      if (items.length) newestId = Math.max(newestId, items[0].id);
      errorBox.replaceChildren();
      render(appendPage ? -1 : keepCount ? prevNewest : -1);
    } catch (e) {
      if (isAbort(e)) return;
      errorBox.replaceChildren(banner("error", "Das Protokoll konnte nicht geladen werden.", e.message));
    } finally {
      more.disabled = false;
    }
  }

  function render(freshAbove) {
    tbody.replaceChildren(...items.map((x) => row(x, freshAbove > 0 && x.id > freshAbove)));
    more.hidden = !nextBefore;
    const filtered = state.search || state.client || state.status !== "all";
    emptyBox.hidden = items.length > 0;
    table.hidden = items.length === 0;
    emptyBox.replaceChildren(
      h("h2", {}, filtered ? "Keine passenden Abfragen" : "Noch keine Abfragen"),
      h("p", {}, filtered ? "Ändere die Filter oder suche nach einem anderen Begriff." : "Sobald Geräte PK95 DNS als DNS-Server nutzen, erscheinen ihre Anfragen hier."));
  }

  function row(x, fresh) {
    const blocked = x.status === "blocked" || x.status === "blocked_service";
    const detail = decisionDetail(x, catalog);
    const action = !QUICKABLE.test(x.name || "") ? null : blocked
      ? h("button", { type: "button", class: "small", "aria-label": `${x.name} freigeben`, title: `${x.name} freigeben (eigene Regel @@||${x.name}^)`, onclick: (e) => quick(e.currentTarget, x.name, "allow") }, "Freigeben")
      : h("button", { type: "button", class: "small danger", "aria-label": `${x.name} sperren`, title: `${x.name} sperren (eigene Regel ||${x.name}^)`, onclick: (e) => quick(e.currentTarget, x.name, "block") }, "Sperren");
    return h("tr", { class: fresh ? "fresh" : "" },
      h("td", { class: "nowrap", title: fmtFull.format(new Date(x.ts)) }, fmtLogTime(x.ts)),
      h("td", { class: "wrap" },
        h("a", { href: "#/log?client=" + encodeURIComponent(x.client_ip), title: "Nur diesen Client zeigen", onclick: (e) => { e.preventDefault(); client.value = x.client_ip; changed(); } }, x.client_name || x.client_ip),
        x.client_name ? h("span", { class: "cell-sub" }, x.client_ip) : null),
      h("td", { class: "domain" }, x.name, " ", h("span", { class: "tag mono" }, x.qtype)),
      h("td", { class: "status-cell" },
        statusBadge(x.status, x.cached),
        detail ? h("span", { class: "cell-sub" }, detail) : null,
        x.rule ? h("span", { class: "cell-sub mono", title: "Regel" }, x.rule) : null),
      h("td", { class: "answer" },
        x.answer || (x.rcode && x.rcode !== "NOERROR" ? "" : h("span", { class: "muted" }, "–")),
        x.rcode && x.rcode !== "NOERROR" ? h("span", { class: "cell-sub" }, x.rcode) : null),
      h("td", { class: "num" }, fmtMs(x.elapsed_ms), x.cached ? h("span", { class: "cell-sub" }, "Cache") : null),
      h("td", { class: "upstream", title: x.upstream || "" }, x.upstream || h("span", { class: "muted" }, "–")),
      h("td", { class: "actions-cell" }, action));
  }

  async function quick(btn, domain, action) {
    btn.disabled = true;
    try {
      await quickRule(domain, action, ctx.signal);
    } catch (e) {
      if (e && e.fields && e.fields.domain) e.message = e.fields.domain;
      toastError(e);
    }
    btn.disabled = false;
  }

  function clearLog() {
    confirmDialog({
      title: "Protokoll leeren?",
      text: "Alle gespeicherten Abfragen werden gelöscht. Die Statistik bleibt erhalten.",
      confirm: "Protokoll leeren",
      action: async () => {
        await ctx.api("querylog", { method: "DELETE" });
        toast("Das Abfrageprotokoll ist leer.");
        items = [];
        nextBefore = 0;
        load(false);
      },
    });
  }

  const live = ctx.poll(() => load(false, true), 5000);
  live.set(auto.input.checked);
  if (!auto.input.checked) load(false);
};

// --- Blocklisten -----------------------------------------------------------

VIEWS.lists = function viewLists(root, params, ctx) {
  let lists = [];
  let pollUntil = 0;
  let timer = null;
  const blockBox = h("div", { class: "list-rows" });
  const allowBox = h("div", { class: "list-rows" });
  const errorBox = h("div");
  const refreshAll = h("button", { type: "button", onclick: refreshEverything }, icon(ICONS.refresh), "Alle aktualisieren");

  root.append(
    h("div", { class: "page-head" }, h("h1", {}, "Blocklisten"),
      h("div", { class: "actions" }, refreshAll,
        h("button", { type: "button", class: "primary", onclick: () => addDialog() }, icon(ICONS.plus), "Liste hinzufügen"))),
    h("p", { class: "page-intro" }, "Blocklisten sperren Werbung, Tracker und Schadsoftware. Erlaubnislisten haben Vorrang und geben Domains wieder frei."),
    errorBox,
    h("div", { class: "stack" },
      h("section", { class: "card" }, h("h2", {}, "Blocklisten"), blockBox),
      h("section", { class: "card" }, h("h2", {}, "Erlaubnislisten"), allowBox)));
  ctx.on(() => clearTimeout(timer));

  async function load() {
    clearTimeout(timer);
    try {
      lists = await ctx.api("lists");
      errorBox.replaceChildren();
      render();
    } catch (e) {
      if (isAbort(e)) return;
      errorBox.replaceChildren(banner("error", "Die Listen konnten nicht geladen werden.", e.message));
    }
    // While any list is updating (or right after a refresh was started) poll every 2 s.
    if (!ctx.dead && (lists.some((l) => l.updating) || Date.now() < pollUntil)) timer = setTimeout(load, 2000);
  }

  function watch() {
    pollUntil = Date.now() + 5000;
    clearTimeout(timer);
    timer = setTimeout(load, 600);
  }

  function render() {
    const busy = lists.some((l) => l.updating);
    refreshAll.disabled = busy;
    refreshAll.replaceChildren(busy ? h("span", { class: "spinner", "aria-hidden": "true" }) : icon(ICONS.refresh), busy ? "Wird aktualisiert …" : "Alle aktualisieren");
    for (const [kind, box] of [["block", blockBox], ["allow", allowBox]]) {
      const own = lists.filter((l) => l.kind === kind);
      box.replaceChildren(...(own.length ? own.map(listRow) : [h("p", { class: "empty" },
        kind === "block" ? "Noch keine Blockliste. Füge eine aus dem Katalog hinzu." : "Keine Erlaubnisliste. Die brauchst du nur, wenn Blocklisten zu viel sperren.")]));
    }
  }

  function listRow(l) {
    const sw = toggle(`${l.name} aktiv`, l.enabled, {
      onchange: async () => {
        sw.input.disabled = true;
        try {
          await ctx.api("lists/" + l.id, { method: "PUT", body: { name: l.name, url: l.url, kind: l.kind, enabled: sw.input.checked } });
          toast(sw.input.checked ? `„${l.name}“ ist aktiv.` : `„${l.name}“ ist ausgeschaltet.`);
          if (sw.input.checked) watch(); else load();
        } catch (e) {
          sw.input.checked = !sw.input.checked;
          toastError(e);
        }
        sw.input.disabled = false;
      },
    });
    sw.el.querySelector("span").className = "sr-only";
    const meta = [];
    if (l.updating) meta.push(h("span", { class: "state" }, h("span", { class: "spinner", "aria-hidden": "true" }), "Wird aktualisiert …"));
    if (l.updated_at) {
      meta.push(h("span", {}, plural(l.rule_count, "Regel", "Regeln")));
      meta.push(h("span", { title: fmtFull.format(new Date(l.updated_at)) }, "aktualisiert " + fmtAgo(l.updated_at)));
    } else if (!l.updating) {
      meta.push(h("span", { class: "muted" }, l.enabled ? "Noch nicht geladen" : "Ausgeschaltet, nicht geladen"));
    }
    return h("div", { class: "list-row" + (l.enabled ? "" : " off") },
      sw.el,
      h("div", { class: "list-text" },
        h("div", { class: "list-name" }, l.name, l.enabled ? null : h("span", { class: "badge" }, "Aus")),
        h("div", { class: "list-url" }, l.url),
        h("div", { class: "list-meta" }, meta),
        l.last_error ? h("div", { class: "small error-text" }, "Letzter Fehler: " + l.last_error + (l.updated_at ? " (die zuletzt geladene Fassung bleibt in Gebrauch)" : "")) : null),
      h("div", { class: "row-actions" },
        h("button", { type: "button", class: "icon-only small ghost", title: "Jetzt aktualisieren", "aria-label": `${l.name} jetzt aktualisieren`, disabled: l.updating || !l.enabled, onclick: () => refreshOne(l) }, icon(ICONS.refresh)),
        h("button", { type: "button", class: "icon-only small ghost", title: "Bearbeiten", "aria-label": `${l.name} bearbeiten`, onclick: () => editDialog(l) }, icon(ICONS.edit)),
        h("button", { type: "button", class: "icon-only small ghost danger", title: "Entfernen", "aria-label": `${l.name} entfernen`, onclick: () => removeList(l) }, icon(ICONS.trash))));
  }

  async function refreshOne(l) {
    try {
      await ctx.api(`lists/${l.id}/refresh`, { method: "POST" });
      l.updating = true;
      render();
      watch();
    } catch (e) { toastError(e); }
  }

  async function refreshEverything() {
    refreshAll.disabled = true;
    try {
      await ctx.api("lists/refresh", { method: "POST" });
      toast("Alle aktiven Listen werden aktualisiert.");
      lists.forEach((l) => { if (l.enabled) l.updating = true; });
      render();
      watch();
    } catch (e) {
      toastError(e);
      refreshAll.disabled = false;
    }
  }

  function removeList(l) {
    confirmDialog({
      title: `„${l.name}“ entfernen?`,
      text: "Die Liste und ihre gespeicherte Kopie werden gelöscht. Ihre Regeln gelten sofort nicht mehr.",
      confirm: "Entfernen",
      action: async () => {
        await ctx.api("lists/" + l.id, { method: "DELETE" });
        toast(`„${l.name}“ wurde entfernt.`);
        load();
      },
    });
  }

  // Shared form for "own URL" and edit.
  function listForm(l, submitLabel, onSaved, onCancel) {
    const general = h("div", { class: "form-error", role: "alert", hidden: true });
    const scope = errorScope(general);
    const name = h("input", { type: "text", maxLength: 80, value: l ? l.name : "", required: true });
    const url = h("input", { type: "url", value: l ? l.url : "", required: true, placeholder: "https://…", spellcheck: false });
    const kindName = nextId("kind");
    const kinds = [["block", "Blockliste", "sperrt die enthaltenen Domains"], ["allow", "Erlaubnisliste", "gibt die enthaltenen Domains frei"]].map(([v, label, hint]) => {
      const r = h("input", { type: "radio", name: kindName, value: v, checked: (l ? l.kind : "block") === v });
      return { r, el: h("label", { class: "check" }, r, h("span", {}, label, " ", h("span", { class: "muted" }, "– " + hint))) };
    });
    const kindErr = h("div", { class: "field-error", role: "alert", hidden: true });
    scope.register("kind", { err: kindErr, inputs: kinds.map((k) => k.r) });
    const enabled = toggle("Aktiv", l ? l.enabled : true);
    const save = h("button", { type: "submit", class: "primary" }, submitLabel);
    const form = h("form", {
      class: "stack",
      onsubmit: async (e) => {
        e.preventDefault();
        scope.clear();
        save.disabled = true;
        const body = { name: name.value.trim(), url: url.value.trim(), kind: kinds.find((k) => k.r.checked).r.value, enabled: enabled.input.checked };
        try {
          const saved = await ctx.api(l ? "lists/" + l.id : "lists", { method: l ? "PUT" : "POST", body });
          onSaved(saved);
        } catch (ex) {
          if (isAbort(ex)) return;
          scope.show(ex);
          save.disabled = false;
        }
      },
    },
      general,
      field(scope, "name", "Name", name),
      field(scope, "url", "Adresse (URL)", url, { hint: "Hosts-Dateien, Domainlisten und AdGuard/Adblock-Filter werden erkannt." }),
      h("fieldset", { class: "radio-list" }, h("legend", {}, "Art"), kinds.map((k) => k.el), kindErr),
      enabled.el,
      h("div", { class: "dialog-foot" }, h("button", { type: "button", onclick: onCancel }, "Abbrechen"), save));
    return { form, focus: () => name.focus() };
  }

  function editDialog(l) {
    const f = listForm(l, "Speichern", (saved) => {
      dlg.close();
      toast(`„${saved.name}“ gespeichert.`);
      if (saved.enabled) watch(); else load();
    }, () => dlg.close());
    const dlg = openDialog("Liste bearbeiten", f.form);
    f.focus();
  }

  function addDialog() {
    const tabs = [["catalog", "Aus dem Katalog"], ["custom", "Eigene Adresse"]];
    const panels = {};
    const tabButtons = tabs.map(([id, label]) => h("button", {
      type: "button", role: "tab", id: "tab-" + id, "aria-controls": "panel-" + id, "aria-selected": String(id === "catalog"),
      onclick: () => select(id),
      onkeydown: (e) => {
        if (e.key === "ArrowRight" || e.key === "ArrowLeft") { e.preventDefault(); const next = id === "catalog" ? "custom" : "catalog"; select(next); tabButtons[next === "catalog" ? 0 : 1].focus(); }
      },
      tabIndex: id === "catalog" ? 0 : -1,
    }, label));
    function select(id) {
      tabButtons.forEach((b, i) => { const on = tabs[i][0] === id; b.setAttribute("aria-selected", String(on)); b.tabIndex = on ? 0 : -1; });
      for (const [k, p] of Object.entries(panels)) p.hidden = k !== id;
    }
    const catalogBox = h("div", { class: "catalog" }, h("p", { class: "muted" }, "Katalog wird geladen …"));
    panels.catalog = h("div", { role: "tabpanel", id: "panel-catalog", "aria-labelledby": "tab-catalog" }, catalogBox);
    const custom = listForm(null, "Hinzufügen", (saved) => {
      dlg.close();
      toast(`„${saved.name}“ hinzugefügt${saved.enabled ? " und wird geladen" : ""}.`);
      watch();
    }, () => dlg.close());
    panels.custom = h("div", { role: "tabpanel", id: "panel-custom", "aria-labelledby": "tab-custom", hidden: true }, custom.form);
    const dlg = openDialog("Liste hinzufügen", [
      h("div", { class: "segmented", role: "tablist", "aria-label": "Quelle" }, tabButtons),
      panels.catalog, panels.custom,
    ], { wide: true });

    ctx.api("lists/catalog").then((cat) => {
      const have = new Set(lists.map((l) => l.url));
      const groups = [["block", "Blocklisten"], ["allow", "Erlaubnislisten"]];
      catalogBox.replaceChildren(...groups.flatMap(([kind, title]) => {
        const items = (cat || []).filter((c) => c.kind === kind);
        if (!items.length) return [];
        return [h("div", { class: "catalog-title" }, title), ...items.map((c) => {
          const added = have.has(c.url);
          const btn = h("button", {
            type: "button", class: added ? "small" : "small primary", disabled: added,
            "aria-label": added ? `${c.name} ist bereits hinzugefügt` : `${c.name} hinzufügen`,
            onclick: async () => {
              btn.disabled = true;
              try {
                await ctx.api("lists", { method: "POST", body: { name: c.name, url: c.url, kind: c.kind, enabled: true } });
                have.add(c.url);
                btn.textContent = "Hinzugefügt";
                btn.className = "small";
                toast(`„${c.name}“ hinzugefügt und wird geladen.`);
                watch();
              } catch (e) {
                toastError(e);
                btn.disabled = false;
              }
            },
          }, added ? "Hinzugefügt" : "Hinzufügen");
          return h("div", { class: "catalog-item" },
            h("div", {}, h("div", { class: "list-name" }, c.name),
              c.description ? h("div", { class: "desc" }, c.description) : null,
              h("div", { class: "url" }, c.url)),
            btn);
        })];
      }));
      if (!catalogBox.children.length) catalogBox.replaceChildren(h("p", { class: "muted" }, "Der Katalog ist leer."));
    }, (e) => {
      if (!isAbort(e)) catalogBox.replaceChildren(h("div", { class: "form-error" }, e.message));
    });
  }

  load();
};

// --- Eigene Regeln ---------------------------------------------------------

const RULE_HELP = [
  ["||example.org^", "sperrt example.org und alle Subdomains"],
  ["example.org", "sperrt genau diese Domain (auch |example.org^)"],
  ["*.example.org", "sperrt alle Subdomains, nicht die Domain selbst"],
  ["@@||example.org^", "gibt example.org und alle Subdomains frei"],
  ["/^ad[0-9]+\\./", "regulärer Ausdruck (RE2), @@/…/ gibt frei"],
  ["||ads*.example.org^", "* als Platzhalter innerhalb eines Musters"],
  ["0.0.0.0 tracker.example", "Hosts-Schreibweise: sperrt genau diese Namen"],
  ["192.168.1.5 nas.lan", "Hosts-Schreibweise mit Adresse: antwortet mit dieser IP"],
  ["||example.org^$important", "hat Vorrang vor Freigaben"],
  ["||example.org^$dnstype=AAAA", "gilt nur für diese Typen (~AAAA schließt aus)"],
  ["! Kommentar", "Kommentare beginnen mit ! oder #"],
];

const QTYPES = ["A", "AAAA", "CNAME", "HTTPS", "MX", "TXT", "PTR", "SRV", "NS", "SOA"];

VIEWS.rules = function viewRules(root, params, ctx) {
  let saved = "";
  let invalid = [];
  let catalog = null;
  loadServiceCatalog().then((c) => { catalog = c; }, () => {});

  const gutter = h("pre", { class: "gutter", "aria-hidden": "true" });
  const text = h("textarea", {
    id: "rules-text", spellcheck: false, autocapitalize: "none", autocomplete: "off", wrap: "off",
    placeholder: "||werbung.example^\n@@||erlaubt.example^", "aria-describedby": "rules-state",
  });
  const editor = h("div", { class: "editor" }, gutter, text);
  const stateEl = h("span", { id: "rules-state", class: "small muted", "aria-live": "polite" });
  const save = h("button", { type: "button", class: "primary", onclick: saveRules }, "Speichern");
  const revert = h("button", { type: "button", onclick: () => { text.value = saved; refresh(); } }, "Verwerfen");
  const invalidBox = h("div");
  const errorBox = h("div");

  root.append(
    h("div", { class: "page-head" }, h("h1", {}, "Eigene Regeln")),
    errorBox,
    h("div", { class: "grid-2" },
      h("section", { class: "card", style: "grid-column: 1 / -1" },
        h("div", { class: "card-head" }, h("h2", {}, h("label", { for: "rules-text" }, "Regeln")), h("span", { class: "small muted" }, "Eine Regel pro Zeile · Strg/⌘ + S speichert")),
        editor,
        h("div", { class: "editor-foot" }, stateEl, h("span", { class: "spacer" }), revert, save),
        invalidBox),
      checkCard(),
      h("section", { class: "card" },
        h("h2", {}, "Kurzanleitung"),
        h("table", { class: "syntax" }, h("tbody", {}, RULE_HELP.map(([rule, desc]) => h("tr", {}, h("td", {}, h("code", {}, rule)), h("td", {}, desc))))),
        h("p", { class: "hint", style: "margin-top:10px" }, "Eigene Regeln gehen den Blocklisten vor. Ungültige Zeilen werden gespeichert, aber ignoriert."))));

  const dirty = () => text.value !== saved;
  const updateGutter = () => {
    const count = text.value.split("\n").length;
    const bad = new Set(invalid.map((x) => x.line));
    const frag = document.createDocumentFragment();
    for (let i = 1; i <= count; i++) {
      if (bad.has(i)) frag.append(h("span", { class: "bad" }, String(i)));
      else frag.append(String(i));
      if (i < count) frag.append("\n");
    }
    gutter.replaceChildren(frag);
    gutter.scrollTop = text.scrollTop;
  };
  function refresh() {
    updateGutter();
    save.disabled = !dirty();
    revert.hidden = !dirty();
    stateEl.textContent = dirty() ? "Ungespeicherte Änderungen" : "";
  }
  let raf = 0;
  text.addEventListener("input", () => { cancelAnimationFrame(raf); raf = requestAnimationFrame(refresh); });
  text.addEventListener("scroll", () => { gutter.scrollTop = text.scrollTop; });
  text.addEventListener("keydown", (e) => {
    if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === "s") { e.preventDefault(); if (dirty()) saveRules(); }
  });
  const beforeUnload = (e) => { if (dirty()) { e.preventDefault(); e.returnValue = ""; } };
  window.addEventListener("beforeunload", beforeUnload);
  ctx.on(() => window.removeEventListener("beforeunload", beforeUnload));

  function apply(res, keepText) {
    saved = res.text || "";
    if (!keepText) text.value = saved;
    invalid = res.invalid || [];
    refresh();
    stateEl.textContent = dirty() ? "Ungespeicherte Änderungen" : `${plural(res.rule_count || 0, "aktive Regel", "aktive Regeln")}${invalid.length ? `, ${plural(invalid.length, "ungültige Zeile", "ungültige Zeilen")}` : ""}`;
    invalidBox.replaceChildren(invalid.length ? h("div", {},
      h("h3", { style: "margin-top:14px" }, "Ungültige Zeilen werden ignoriert"),
      h("ul", { class: "invalid-list" }, invalid.map((x) => h("li", {}, h("button", {
        type: "button", title: "Zur Zeile springen", onclick: () => jumpTo(x.line),
      }, h("span", { class: "ln" }, "Zeile " + x.line), h("span", {}, h("code", {}, x.text), h("span", { class: "cell-sub" }, x.error))))))) : "");
  }

  function jumpTo(line) {
    const all = text.value.split("\n");
    let start = 0;
    for (let i = 0; i < line - 1 && i < all.length; i++) start += all[i].length + 1;
    const end = start + (all[line - 1] || "").length;
    text.focus();
    text.setSelectionRange(start, end);
    const lh = 20;
    text.scrollTop = Math.max(0, (line - 4) * lh);
  }

  async function saveRules() {
    save.disabled = true;
    try {
      const res = await ctx.api("rules", { method: "PUT", body: { text: text.value } });
      apply(res);
      toast(res.invalid && res.invalid.length ? `Gespeichert. ${plural(res.invalid.length, "Zeile ist", "Zeilen sind")} ungültig.` : "Regeln gespeichert.");
    } catch (e) {
      if (isAbort(e)) return;
      toastError(e);
      save.disabled = !dirty();
    }
  }

  function checkCard() {
    const general = h("div", { class: "form-error", role: "alert", hidden: true });
    const scope = errorScope(general);
    const name = h("input", { type: "text", placeholder: "werbung.example.com", spellcheck: false, autocapitalize: "none", required: true });
    const type = h("select", {}, QTYPES.map((t) => h("option", { value: t }, t)));
    const client = h("input", { type: "text", placeholder: "optional, z. B. 192.168.1.20", spellcheck: false });
    const go = h("button", { type: "submit", class: "primary" }, "Prüfen");
    const result = h("div", { "aria-live": "polite" });
    async function run() {
      scope.clear();
      const q = new URLSearchParams({ name: name.value.trim(), type: type.value });
      if (client.value.trim()) q.set("client", client.value.trim());
      go.disabled = true;
      try {
        const r = await ctx.api("check?" + q);
        showResult(r);
      } catch (e) {
        if (isAbort(e)) return;
        result.replaceChildren();
        scope.show(e);
      } finally {
        go.disabled = false;
      }
    }
    function showResult(r) {
      const verdict = {
        ok: "Wird nicht gefiltert",
        allowed: "Ausdrücklich erlaubt",
        blocked: "Wird blockiert",
        blocked_service: "Wird blockiert (Dienst)",
        safesearch: "SafeSearch greift",
        rewrite: "Wird umgeschrieben",
        refused: "Wird abgewiesen",
        error: "Fehler",
      }[r.status] || r.status;
      const explain = {
        ok: "Keine Regel greift. Die Anfrage geht an den Upstream-DNS.",
        allowed: "Eine Freigabe-Regel greift, die Anfrage geht an den Upstream-DNS.",
        safesearch: "Die Suchmaschine wird auf ihre jugendfreie Variante umgeleitet.",
      }[r.status];
      const rows = [];
      const add = (k, v) => { if (v) rows.push(h("dt", {}, k), h("dd", {}, v)); };
      add("Grund", decisionDetail(r, catalog));
      add("Regel", r.rule ? h("code", {}, r.rule) : "");
      add("Antwort", r.answer);
      add("Client", r.client_ip ? `${r.client_name ? r.client_name + " – " : ""}${r.client_ip}` : "");
      const blocked = r.status === "blocked" || r.status === "blocked_service";
      const actions = h("div", { class: "form-foot" });
      if (!dirty()) {
        actions.append(blocked
          ? h("button", { type: "button", class: "small", onclick: () => quickAndRecheck("allow") }, `${r.name} freigeben`)
          : h("button", { type: "button", class: "small danger", onclick: () => quickAndRecheck("block") }, `${r.name} sperren`));
      } else {
        actions.append(h("span", { class: "hint" }, "Speichere deine Änderungen an den Regeln, um von hier aus zu sperren oder freizugeben."));
      }
      async function quickAndRecheck(action) {
        try {
          const res = await quickRule(r.name, action, ctx.signal);
          apply(res);
          run();
        } catch (e) { toastError(e); }
      }
      result.replaceChildren(h("div", { class: "check-result" },
        h("div", { class: "verdict" }, statusBadge(r.status), h("span", {}, `${r.name} (${r.type})`), h("span", { class: "ink-2", style: "font-weight:500" }, verdict)),
        explain ? h("div", { class: "ink-2" }, explain) : null,
        rows.length ? h("dl", {}, rows) : null,
        actions));
    }
    return h("section", { class: "card" },
      h("h2", {}, "Domain prüfen"),
      h("p", { class: "card-intro" }, "Zeigt, wie PK95 DNS eine Anfrage beantworten würde, ohne einen Upstream zu fragen."),
      h("form", { class: "stack", onsubmit: (e) => { e.preventDefault(); run(); } },
        general,
        h("div", { class: "check-form" },
          field(scope, "name", "Domain", name, { class: "wide-cell" }),
          field(scope, "type", "Typ", type),
          field(scope, "client", "Client-IP", client, { class: "wide-cell" }),
          h("div", { class: "field" }, go))),
      result);
  }

  ctx.api("rules").then((res) => apply(res), (e) => {
    if (!isAbort(e)) errorBox.replaceChildren(banner("error", "Die Regeln konnten nicht geladen werden.", e.message));
  });
  refresh();
};

// --- Lokale Einträge (rewrites) --------------------------------------------

function answerKind(answer) {
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(answer)) return "IPv4";
  if (answer.includes(":")) return "IPv6";
  return "CNAME";
}

VIEWS.rewrites = function viewRewrites(root, params, ctx) {
  let rows = [];
  const filter = h("input", { type: "search", placeholder: "Einträge durchsuchen", "aria-label": "Einträge durchsuchen", spellcheck: false });
  const tbody = h("tbody");
  const table = h("table", { class: "resp-table" },
    h("thead", {}, h("tr", {},
      h("th", { scope: "col" }, "Aktiv"), h("th", { scope: "col" }, "Domain"), h("th", { scope: "col" }, "Antwort"),
      h("th", { scope: "col" }, h("span", { class: "sr-only" }, "Aktionen")))),
    tbody);
  const emptyBox = h("div", { class: "empty-state", hidden: true });
  const errorBox = h("div");

  root.append(
    h("div", { class: "page-head" }, h("h1", {}, "Lokale Einträge"),
      h("div", { class: "actions" }, h("button", { type: "button", class: "primary", onclick: () => editDialog(null) }, icon(ICONS.plus), "Eintrag hinzufügen"))),
    h("p", { class: "page-intro" }, "Eigene DNS-Antworten für Geräte im Heimnetz, zum Beispiel nas.home.lan → 192.168.1.10. Sie gelten immer, auch wenn der Schutz pausiert ist."),
    errorBox,
    h("div", { class: "grid-2" },
      h("section", { class: "card", style: "grid-column: 1 / -1" },
        h("div", { class: "filters" }, filter),
        h("div", { class: "table-wrap" }, table, emptyBox)),
      h("section", { class: "card", style: "grid-column: 1 / -1" },
        h("h2", {}, "Gut zu wissen"),
        h("ul", { class: "ink-2", style: "margin:0;padding-left:18px;display:grid;gap:4px" },
          h("li", {}, h("code", {}, "*.home.lan"), " gilt für alle Subdomains, aber nicht für ", h("code", {}, "home.lan"), " selbst. Genaue Einträge haben Vorrang vor Platzhaltern."),
          h("li", {}, "Eine IPv4-Adresse beantwortet A-Anfragen, eine IPv6-Adresse AAAA-Anfragen. Mehrere Einträge für dieselbe Domain sind möglich."),
          h("li", {}, "Ein Hostname als Antwort wird als CNAME ausgeliefert und weiter aufgelöst, zum Beispiel ", h("code", {}, "fotos.home.lan → nas.home.lan"), ".")))));
  filter.addEventListener("input", render);

  async function load() {
    try {
      rows = await ctx.api("rewrites");
      errorBox.replaceChildren();
      render();
    } catch (e) {
      if (!isAbort(e)) errorBox.replaceChildren(banner("error", "Die lokalen Einträge konnten nicht geladen werden.", e.message));
    }
  }

  function render() {
    const q = filter.value.trim().toLowerCase();
    const shown = rows.filter((r) => !q || r.domain.toLowerCase().includes(q) || r.answer.toLowerCase().includes(q));
    tbody.replaceChildren(...shown.map((r) => {
      const sw = toggle(`${r.domain} aktiv`, r.enabled, {
        onchange: async () => {
          sw.input.disabled = true;
          try {
            const saved = await ctx.api("rewrites/" + r.id, { method: "PUT", body: { domain: r.domain, answer: r.answer, enabled: sw.input.checked } });
            Object.assign(r, saved);
            render();
          } catch (e) {
            sw.input.checked = !sw.input.checked;
            toastError(e);
            sw.input.disabled = false;
          }
        },
      });
      sw.el.querySelector("span").className = "sr-only";
      return h("tr", { class: r.enabled ? "" : "off" },
        h("td", { style: "width:60px" }, sw.el),
        h("td", { class: "wrap", "data-label": "Domain" }, h("strong", {}, r.domain)),
        h("td", { class: "wrap", "data-label": "Antwort" }, h("span", { class: "mono" }, r.answer), " ", h("span", { class: "tag" }, answerKind(r.answer))),
        h("td", { class: "actions-cell" }, h("div", { class: "row-actions" },
          h("button", { type: "button", class: "small", onclick: () => editDialog(r) }, "Bearbeiten"),
          h("button", { type: "button", class: "small danger", onclick: () => remove(r) }, "Löschen"))));
    }));
    table.hidden = shown.length === 0;
    emptyBox.hidden = shown.length > 0;
    fill(emptyBox, rows.length
      ? h("p", {}, "Kein Eintrag passt zur Suche.")
      : [h("h2", {}, "Noch keine lokalen Einträge"), h("p", {}, "Lege Namen für Geräte in deinem Netz an, dann musst du dir keine IP-Adressen merken.")]);
  }

  function remove(r) {
    confirmDialog({
      title: `${r.domain} löschen?`,
      text: `Der Eintrag ${r.domain} → ${r.answer} wird gelöscht.`,
      confirm: "Löschen",
      action: async () => {
        await ctx.api("rewrites/" + r.id, { method: "DELETE" });
        toast(`${r.domain} gelöscht.`);
        load();
      },
    });
  }

  function editDialog(r) {
    const general = h("div", { class: "form-error", role: "alert", hidden: true });
    const scope = errorScope(general);
    const domain = h("input", { type: "text", value: r ? r.domain : "", placeholder: "nas.home.lan oder *.home.lan", spellcheck: false, autocapitalize: "none", required: true });
    const answer = h("input", { type: "text", value: r ? r.answer : "", placeholder: "192.168.1.10, fd00::10 oder nas.home.lan", spellcheck: false, autocapitalize: "none", required: true });
    const enabled = toggle("Aktiv", r ? r.enabled : true);
    const save = h("button", { type: "submit", class: "primary" }, r ? "Speichern" : "Hinzufügen");
    const form = h("form", {
      class: "stack",
      onsubmit: async (e) => {
        e.preventDefault();
        scope.clear();
        save.disabled = true;
        try {
          await ctx.api(r ? "rewrites/" + r.id : "rewrites", { method: r ? "PUT" : "POST", body: { domain: domain.value.trim(), answer: answer.value.trim(), enabled: enabled.input.checked } });
          dlg.close();
          toast(r ? "Eintrag gespeichert." : "Eintrag hinzugefügt.");
          load();
        } catch (ex) {
          if (isAbort(ex)) return;
          scope.show(ex);
          save.disabled = false;
        }
      },
    },
      general,
      field(scope, "domain", "Domain", domain, { hint: "*.home.lan gilt für alle Subdomains, nicht für home.lan selbst." }),
      field(scope, "answer", "Antwort", answer, { hint: "IPv4- oder IPv6-Adresse, oder ein Hostname (wird als CNAME beantwortet)." }),
      enabled.el,
      h("div", { class: "dialog-foot" }, h("button", { type: "button", onclick: () => dlg.close() }, "Abbrechen"), save));
    const dlg = openDialog(r ? "Eintrag bearbeiten" : "Lokaler Eintrag", form);
    domain.focus();
  }

  load();
};

// --- Dienste ---------------------------------------------------------------

function groupedServices(catalog) {
  return SERVICE_GROUPS
    .map(([id, title]) => ({ id, title, items: catalog.services.filter((x) => (x.group || "other") === id) }))
    .concat([{ id: "_rest", title: "Sonstiges", items: catalog.services.filter((x) => !SERVICE_GROUPS.some(([g]) => g === (x.group || "other"))) }])
    .filter((g) => g.items.length);
}

VIEWS.services = function viewServices(root, params, ctx) {
  let catalog = null;
  let saved = new Set();
  let blocked = new Set();
  const inputs = new Map();
  const box = h("div", { class: "service-groups" });
  const filter = h("input", { type: "search", placeholder: "Dienst suchen", "aria-label": "Dienst suchen" });
  const countEl = h("span", { "aria-live": "polite" });
  const save = h("button", { type: "button", class: "primary", onclick: saveServices }, "Speichern");
  const revert = h("button", { type: "button", onclick: () => { blocked = new Set(saved); sync(); } }, "Verwerfen");
  const errorBox = h("div");

  root.append(
    h("div", { class: "page-head" }, h("h1", {}, "Dienste")),
    h("p", { class: "page-intro" }, "Sperre ganze Dienste mit einem Schalter, zum Beispiel TikTok oder Online-Spiele. Das gilt für alle Clients, die keine eigene Auswahl haben."),
    errorBox,
    h("div", { class: "filters" }, filter),
    box,
    h("div", { class: "save-bar" }, countEl, h("span", { class: "spacer" }), revert, save));
  filter.addEventListener("input", () => {
    const q = filter.value.trim().toLowerCase();
    for (const card of box.children) {
      let any = false;
      for (const lbl of card.querySelectorAll(".service-grid .check")) {
        const hit = !q || lbl.dataset.name.includes(q);
        lbl.hidden = !hit;
        any = any || hit;
      }
      card.hidden = !any;
    }
  });

  const dirty = () => saved.size !== blocked.size || [...blocked].some((x) => !saved.has(x));

  function sync() {
    for (const [id, input] of inputs) input.checked = blocked.has(id);
    countEl.textContent = (blocked.size ? plural(blocked.size, "Dienst gesperrt", "Dienste gesperrt") : "Kein Dienst gesperrt") + (dirty() ? " · ungespeichert" : "");
    save.disabled = !dirty();
    revert.hidden = !dirty();
  }

  function render() {
    inputs.clear();
    box.replaceChildren(...groupedServices(catalog).map((g) => {
      const ids = g.items.map((x) => x.id);
      return h("section", { class: "card" },
        h("div", { class: "card-head" }, h("h2", {}, g.title),
          h("div", { class: "actions" },
            h("button", { type: "button", class: "small ghost", "aria-label": `Alle in ${g.title} sperren`, onclick: () => { ids.forEach((id) => blocked.add(id)); sync(); } }, "Alle sperren"),
            h("button", { type: "button", class: "small ghost", "aria-label": `Alle in ${g.title} freigeben`, onclick: () => { ids.forEach((id) => blocked.delete(id)); sync(); } }, "Keinen"))),
        h("div", { class: "service-grid" }, g.items.map((x) => {
          const t = toggle(x.name, blocked.has(x.id), {
            onchange: () => { if (t.input.checked) blocked.add(x.id); else blocked.delete(x.id); sync(); },
          });
          t.el.dataset.name = x.name.toLowerCase();
          t.el.title = `${x.name} sperren`;
          inputs.set(x.id, t.input);
          return t.el;
        })));
    }));
    sync();
  }

  async function saveServices() {
    save.disabled = true;
    try {
      const res = await ctx.api("services", { method: "PUT", body: { blocked: [...blocked] } });
      saved = new Set(res.blocked || []);
      blocked = new Set(saved);
      sync();
      toast("Dienste gespeichert.");
    } catch (e) {
      if (isAbort(e)) return;
      toastError(e);
      save.disabled = !dirty();
    }
  }

  ctx.api("services").then((res) => {
    catalog = res;
    saved = new Set(res.blocked || []);
    blocked = new Set(saved);
    render();
  }, (e) => {
    if (!isAbort(e)) errorBox.replaceChildren(banner("error", "Die Dienste konnten nicht geladen werden.", e.message));
  });
};

// Service picker with plain checkboxes, used in the client dialog.
function servicePicker(catalog, selected) {
  const chosen = new Set(selected || []);
  const el = h("div", { class: "picker" }, groupedServices(catalog).map((g) => h("div", { class: "picker-group", role: "group", "aria-label": g.title },
    h("div", { class: "picker-title" }, g.title),
    h("div", { class: "picker-items" }, g.items.map((x) => {
      const t = toggle(x.name, chosen.has(x.id), { plain: true, onchange: () => { if (t.input.checked) chosen.add(x.id); else chosen.delete(x.id); } });
      return t.el;
    })))));
  return { el, get: () => [...chosen] };
}

// --- Clients ---------------------------------------------------------------

VIEWS.clients = function viewClients(root, params, ctx) {
  let data = { clients: [], recent: [] };
  let catalog = null;
  const listBox = h("div");
  const recentBox = h("div");
  const errorBox = h("div");

  root.append(
    h("div", { class: "page-head" }, h("h1", {}, "Clients"),
      h("div", { class: "actions" }, h("button", { type: "button", class: "primary", onclick: () => editDialog(null) }, icon(ICONS.plus), "Client anlegen"))),
    h("p", { class: "page-intro" }, "Gib Geräten Namen und eigene Regeln, zum Beispiel SafeSearch und gesperrte Dienste nur für das Kinder-Tablet."),
    errorBox,
    h("div", { class: "stack" },
      h("section", { class: "card" }, h("h2", {}, "Eingerichtete Clients"), listBox),
      h("section", { class: "card" }, h("h2", {}, "Zuletzt gesehen"), h("p", { class: "card-intro" }, "Geräte, die in den letzten 24 Stunden gefragt haben."), recentBox)));

  async function load() {
    try {
      const [d, c] = await Promise.all([ctx.api("clients"), loadServiceCatalog().catch(() => null)]);
      data = d || { clients: [], recent: [] };
      catalog = c;
      errorBox.replaceChildren();
      render();
    } catch (e) {
      if (!isAbort(e)) errorBox.replaceChildren(banner("error", "Die Clients konnten nicht geladen werden.", e.message));
    }
  }

  function settingsSummary(c) {
    if (c.use_global_settings) return h("span", { class: "muted" }, "Globale Einstellungen");
    const parts = [c.filtering_enabled ? "Filter an" : "Filter aus"];
    if (c.safesearch && c.safesearch.enabled) parts.push("SafeSearch");
    return h("span", {}, parts.join(", "));
  }

  function servicesSummary(c) {
    if (c.use_global_services) return h("span", { class: "muted" }, "Globale Auswahl");
    const n = (c.blocked_services || []).length;
    if (!n) return h("span", {}, "Keine gesperrt");
    const names = c.blocked_services.map((id) => serviceName(catalog, id));
    return h("span", { title: names.join(", ") }, n <= 3 ? names.join(", ") : plural(n, "Dienst", "Dienste") + " gesperrt");
  }

  function render() {
    const clients = data.clients || [];
    listBox.replaceChildren(clients.length
      ? h("div", { class: "table-wrap" }, h("table", { class: "resp-table" },
        h("thead", {}, h("tr", {}, h("th", { scope: "col" }, "Name"), h("th", { scope: "col" }, "Kennungen"), h("th", { scope: "col" }, "Filter"), h("th", { scope: "col" }, "Dienste"), h("th", { scope: "col" }, h("span", { class: "sr-only" }, "Aktionen")))),
        h("tbody", {}, clients.map((c) => h("tr", {},
          h("td", { class: "wrap" }, h("a", { href: "#/log?client=" + encodeURIComponent(c.name), title: "Abfragen dieses Clients" }, h("strong", {}, c.name))),
          h("td", { "data-label": "Kennungen" }, h("div", { class: "chips" }, (c.ids || []).map((id) => h("span", { class: "chip" }, id)))),
          h("td", { "data-label": "Filter" }, settingsSummary(c)),
          h("td", { "data-label": "Dienste" }, servicesSummary(c)),
          h("td", { class: "actions-cell" }, h("div", { class: "row-actions" },
            h("button", { type: "button", class: "small", onclick: () => editDialog(c) }, "Bearbeiten"),
            h("button", { type: "button", class: "small danger", onclick: () => remove(c) }, "Löschen"))))))))
      : h("div", { class: "empty-state" }, h("h2", {}, "Noch keine Clients eingerichtet"),
        h("p", {}, "Ohne eigene Clients gelten für alle Geräte die globalen Einstellungen. Lege unten aus „Zuletzt gesehen“ einen Client an.")));

    const recent = data.recent || [];
    recentBox.replaceChildren(recent.length
      ? h("div", { class: "table-wrap" }, h("table", { class: "resp-table" },
        h("thead", {}, h("tr", {}, h("th", { scope: "col" }, "Gerät"), h("th", { scope: "col", class: "num" }, "Anfragen"), h("th", { scope: "col", class: "num" }, "Blockiert"), h("th", { scope: "col" }, "Zuletzt"), h("th", { scope: "col" }, h("span", { class: "sr-only" }, "Aktionen")))),
        h("tbody", {}, recent.map((r) => {
          const configured = r.client_id ? clients.find((c) => c.id === r.client_id) : null;
          return h("tr", {},
            h("td", { class: "wrap" },
              h("a", { href: "#/log?client=" + encodeURIComponent(r.ip), title: "Abfragen dieses Geräts" }, h("strong", {}, r.name || r.hostname || r.ip)),
              h("span", { class: "cell-sub" }, [r.ip, r.name && r.hostname ? r.hostname : ""].filter(Boolean).join(" · "))),
            h("td", { class: "num", "data-label": "Anfragen" }, nf.format(r.queries || 0)),
            h("td", { class: "num", "data-label": "Blockiert" }, nf.format(r.blocked || 0)),
            h("td", { class: "nowrap", "data-label": "Zuletzt", title: r.last_seen ? fmtFull.format(new Date(r.last_seen)) : "" }, fmtAgo(r.last_seen)),
            h("td", { class: "actions-cell" }, configured
              ? h("button", { type: "button", class: "small", onclick: () => editDialog(configured) }, "Bearbeiten")
              : h("button", { type: "button", class: "small", onclick: () => editDialog(null, { name: r.hostname || r.ip, ids: [r.ip] }) }, "Als Client anlegen")));
        }))))
      : h("p", { class: "empty" }, "In den letzten 24 Stunden hat noch kein Gerät gefragt."));
  }

  function remove(c) {
    confirmDialog({
      title: `${c.name} löschen?`,
      text: "Für die Geräte dieses Clients gelten danach wieder die globalen Einstellungen.",
      confirm: "Löschen",
      action: async () => {
        await ctx.api("clients/" + c.id, { method: "DELETE" });
        toast(`${c.name} gelöscht.`);
        load();
      },
    });
  }

  function editDialog(c, preset) {
    const x = c || {
      name: (preset && preset.name) || "", ids: (preset && preset.ids) || [],
      use_global_settings: true, filtering_enabled: true,
      safesearch: { enabled: false, google: true, bing: true, duckduckgo: true, youtube: true, yandex: true, pixabay: true },
      use_global_services: true, blocked_services: [],
    };
    const ss = { enabled: false, ...(x.safesearch || {}) };
    const general = h("div", { class: "form-error", role: "alert", hidden: true });
    const scope = errorScope(general);
    const name = h("input", { type: "text", maxLength: 80, value: x.name, required: true });
    const ids = h("textarea", { rows: 3, class: "mono", value: (x.ids || []).join("\n"), spellcheck: false, placeholder: "192.168.1.40\n192.168.50.0/24" });

    const globalSettings = toggle("Globale Filter-Einstellungen verwenden", x.use_global_settings, { onchange: syncVis });
    const filtering = toggle("Filtern (Blocklisten und eigene Regeln)", x.filtering_enabled);
    const ssOn = toggle("SafeSearch erzwingen", ss.enabled, { onchange: syncVis });
    const engines = ENGINES.map(([k, label]) => ({ k, t: toggle(label, ss[k] !== false, { plain: true }) }));
    const enginesBox = h("div", { class: "picker-items", role: "group", "aria-label": "Suchmaschinen" }, engines.map((e) => e.t.el));
    const ssErr = h("div", { class: "field-error", role: "alert", hidden: true });
    scope.register("safesearch", { err: ssErr, inputs: [ssOn.input] });
    const ownSettings = h("fieldset", {}, h("legend", {}, "Eigene Filter-Einstellungen"), filtering.el, ssOn.el, enginesBox, ssErr);

    const globalServices = toggle("Globale Dienste-Auswahl verwenden", x.use_global_services, { onchange: syncVis });
    const picker = catalog ? servicePicker(catalog, x.blocked_services) : null;
    const svcErr = h("div", { class: "field-error", role: "alert", hidden: true });
    scope.register("blocked_services", { err: svcErr, inputs: [] });
    const ownServices = h("fieldset", {}, h("legend", {}, "Gesperrte Dienste für diesen Client"),
      picker ? picker.el : h("p", { class: "muted" }, "Der Dienste-Katalog konnte nicht geladen werden."), svcErr);

    function syncVis() {
      ownSettings.hidden = globalSettings.input.checked;
      enginesBox.hidden = !ssOn.input.checked;
      ownServices.hidden = globalServices.input.checked;
    }
    syncVis();

    const save = h("button", { type: "submit", class: "primary" }, c ? "Speichern" : "Anlegen");
    const form = h("form", {
      class: "stack",
      onsubmit: async (e) => {
        e.preventDefault();
        scope.clear();
        save.disabled = true;
        const safesearch = { enabled: ssOn.input.checked };
        for (const { k, t } of engines) safesearch[k] = t.input.checked;
        const body = {
          name: name.value.trim(),
          ids: lines(ids.value),
          use_global_settings: globalSettings.input.checked,
          filtering_enabled: filtering.input.checked,
          safesearch,
          use_global_services: globalServices.input.checked,
          blocked_services: picker ? picker.get() : x.blocked_services || [],
        };
        try {
          await ctx.api(c ? "clients/" + c.id : "clients", { method: c ? "PUT" : "POST", body });
          dlg.close();
          toast(c ? `${body.name} gespeichert.` : `${body.name} angelegt.`);
          load();
        } catch (ex) {
          if (isAbort(ex)) return;
          // Field errors for ids carry the item index; show the offending entry.
          scope.show(ex);
          save.disabled = false;
        }
      },
    },
      general,
      field(scope, "name", "Name", name),
      field(scope, "ids", "Kennungen", ids, {
        hint: "Eine IP-Adresse oder ein Netz (CIDR) pro Zeile. Die genaueste Angabe gewinnt.",
        describe: (sub, msg) => {
          const item = lines(ids.value)[Number(sub[0])];
          return item ? `${item}: ${msg}` : msg;
        },
      }),
      globalSettings.el, ownSettings,
      globalServices.el, ownServices,
      h("div", { class: "dialog-foot" }, h("button", { type: "button", onclick: () => dlg.close() }, "Abbrechen"), save));
    const dlg = openDialog(c ? "Client bearbeiten" : "Client anlegen", form, { wide: true });
    name.focus();
  }

  load();
};

// --- Einstellungen ---------------------------------------------------------

// Bindings connect one settings key with its control: get() (may throw FieldError), set(value).
function bindLines(scope, key, label, opts = {}) {
  const ta = h("textarea", { rows: opts.rows || 3, class: "mono", spellcheck: false, autocapitalize: "none", placeholder: opts.placeholder || "" });
  if (opts.oninput) ta.addEventListener("input", opts.oninput);
  const el = field(scope, key, label, ta, {
    hint: opts.hint,
    describe: (sub, msg) => {
      const item = lines(ta.value)[Number(sub[0])];
      return item !== undefined ? `${item}: ${msg}` : msg;
    },
  });
  return { key, el, input: ta, get: () => lines(ta.value), set: (v) => { ta.value = (v || []).join("\n"); } };
}

function bindNumber(scope, key, label, opts = {}) {
  const input = h("input", { type: "number", inputMode: "numeric", min: opts.min, max: opts.max, step: 1 });
  const el = field(scope, key, opts.unit ? `${label} (${opts.unit})` : label, input, { hint: opts.hint });
  return { key, el, input, get: () => numberValue(input, key), set: (v) => { input.value = v === undefined || v === null ? "" : String(v); } };
}

function bindText(scope, key, label, opts = {}) {
  const input = h("input", { type: "text", spellcheck: false, autocapitalize: "none", placeholder: opts.placeholder || "" });
  const el = field(scope, key, label, input, { hint: opts.hint });
  return { key, el, input, get: () => input.value.trim(), set: (v) => { input.value = v || ""; } };
}

function bindToggle(scope, key, label, opts = {}) {
  const t = toggle(label, false, { hint: opts.hint, onchange: opts.onchange });
  const err = h("div", { class: "field-error", role: "alert", hidden: true });
  scope.register(key, { err, inputs: [t.input] });
  return { key, el: h("div", { class: "field" }, t.el, err), input: t.input, get: () => t.input.checked, set: (v) => { t.input.checked = !!v; } };
}

function bindSelect(scope, key, label, options, opts = {}) {
  const sel = h("select", { onchange: opts.onchange });
  const el = field(scope, key, label, sel, { hint: opts.hint });
  const fill = (extra) => {
    const all = options.slice();
    if (extra !== undefined && !all.some(([v]) => v === extra)) all.push([extra, opts.custom ? opts.custom(extra) : String(extra)]);
    sel.replaceChildren(...all.map(([v, text]) => h("option", { value: String(v) }, text)));
  };
  return {
    key, el, input: sel,
    get: () => (typeof options[0][0] === "number" ? Number(sel.value) : sel.value),
    set: (v) => { fill(v); sel.value = String(v); },
  };
}

function bindRadio(scope, key, legend, options, opts = {}) {
  const name = nextId("r");
  const radios = options.map(([v, label, hint]) => {
    const r = h("input", { type: "radio", name, value: v, onchange: opts.onchange });
    return { r, el: h("label", { class: "check top" }, r, h("span", { class: "check-text" }, h("span", {}, label), hint ? h("span", { class: "hint" }, hint) : null)) };
  });
  const err = h("div", { class: "field-error", role: "alert", hidden: true });
  scope.register(key, { err, inputs: radios.map((x) => x.r) });
  return {
    key,
    el: h("fieldset", { class: "radio-list" }, h("legend", {}, legend), radios.map((x) => x.el), err),
    get: () => { const on = radios.find((x) => x.r.checked); return on ? on.r.value : options[0][0]; },
    set: (v) => radios.forEach((x) => { x.r.checked = x.r.value === v; }),
  };
}

function bindConditional(scope) {
  const box = h("div", { class: "cond-rows" });
  const err = h("div", { class: "field-error", role: "alert", hidden: true });
  let rows = [];
  const filled = () => rows.filter((r) => r.di.value.trim() || r.ui.value.trim());
  function addRow(domain, upstream) {
    const di = h("input", { type: "text", value: domain || "", placeholder: "fritz.box", spellcheck: false, autocapitalize: "none", "aria-label": "Domain" });
    const ui = h("input", { type: "text", value: upstream || "", placeholder: "192.168.178.1", spellcheck: false, autocapitalize: "none", "aria-label": "Upstream" });
    const entry = { di, ui };
    const rm = h("button", {
      type: "button", class: "icon-only ghost danger", "aria-label": "Zeile entfernen", title: "Zeile entfernen",
      onclick: () => { rows = rows.filter((r) => r !== entry); entry.row.remove(); },
    }, icon(ICONS.trash));
    entry.row = h("div", { class: "cond-row" }, di, ui, rm);
    rows.push(entry);
    box.append(entry.row);
    return di;
  }
  scope.register("conditional", {
    err,
    inputs: [],
    inputsFor: (sub) => {
      const r = filled()[Number(sub[0])];
      if (!r) return [];
      return sub[1] === "domain" ? [r.di] : sub[1] === "upstream" ? [r.ui] : [r.di, r.ui];
    },
    describe: (sub, msg) => {
      const r = filled()[Number(sub[0])];
      return r ? `Zeile ${rows.indexOf(r) + 1}: ${msg}` : msg;
    },
  });
  const el = h("div", { class: "field" },
    h("div", { class: "field-label" }, "Weiterleitungen"),
    h("div", { class: "cond-head", "aria-hidden": "true" }, h("span", {}, "Domain"), h("span", {}, "Upstream"), h("span", {})),
    box,
    h("div", {}, h("button", { type: "button", class: "small", onclick: () => addRow().focus() }, icon(ICONS.plus), "Weiterleitung hinzufügen")),
    h("div", { class: "hint" }, "Anfragen für die Domain und alle Subdomains gehen nur an diesen Upstream, zum Beispiel fritz.box an deinen Router."),
    err);
  return {
    key: "conditional", el,
    get: () => filled().map((r) => ({ domain: r.di.value.trim(), upstream: r.ui.value.trim() })),
    set: (v) => { rows = []; box.replaceChildren(); (v || []).forEach((c) => addRow(c.domain, c.upstream)); },
  };
}

function bindSafeSearch(scope) {
  const on = toggle("SafeSearch für alle Geräte erzwingen", false, { hint: "Gilt für Clients ohne eigene Einstellungen.", onchange: () => sync() });
  const engines = ENGINES.map(([k, label]) => ({ k, t: toggle(label, true, { plain: true }) }));
  const box = h("div", { class: "picker-items", role: "group", "aria-label": "Suchmaschinen und Dienste" }, engines.map((e) => e.t.el));
  const err = h("div", { class: "field-error", role: "alert", hidden: true });
  scope.register("safesearch", { err, inputs: [on.input], describe: (sub, msg) => (sub[0] ? `${(ENGINES.find(([k]) => k === sub[0]) || [0, sub[0]])[1]}: ${msg}` : msg) });
  const sync = () => { box.hidden = !on.input.checked; };
  return {
    key: "safesearch",
    el: h("div", { class: "stack" }, on.el, box, err),
    get: () => {
      const v = { enabled: on.input.checked };
      for (const { k, t } of engines) v[k] = t.input.checked;
      return v;
    },
    set: (v) => {
      v = v || {};
      on.input.checked = !!v.enabled;
      for (const { k, t } of engines) t.input.checked = v[k] !== false;
      sync();
    },
  };
}

// One settings card: saves only its own keys (partial PUT) and shows 422 field errors in place.
function settingsCard(ctx, S, { title, intro, wide, build }) {
  const general = h("div", { class: "form-error", role: "alert", hidden: true });
  const scope = errorScope(general);
  const part = build(scope);
  const save = h("button", { type: "submit", class: "primary" }, "Speichern");
  const fill = (src) => { part.bindings.forEach((b) => b.set(src[b.key])); if (part.after) part.after(); };
  const form = h("form", {
    noValidate: true,
    onsubmit: async (e) => {
      e.preventDefault();
      scope.clear();
      const body = {};
      const local = {};
      for (const b of part.bindings) {
        try { body[b.key] = b.get(); } catch (ex) {
          if (ex instanceof FieldError) local[ex.key] = ex.message; else throw ex;
        }
      }
      if (Object.keys(local).length) { scope.show({ fields: local, message: "" }); return; }
      save.disabled = true;
      try {
        const res = await ctx.api("settings", { method: "PUT", body });
        Object.assign(S, res);
        fill(res);
        toast(`${title}: gespeichert.`);
      } catch (ex) {
        if (!isAbort(ex)) scope.show(ex);
      } finally {
        save.disabled = false;
      }
    },
  }, general, part.nodes, h("div", { class: "form-foot" }, part.extra || null, h("span", { class: "spacer" }), save));
  fill(S);
  return h("section", { class: "card" + (wide ? " wide" : "") }, h("h2", {}, title), intro ? h("p", { class: "card-intro" }, intro) : null, form);
}

VIEWS.settings = function viewSettings(root, params, ctx) {
  const box = h("div", { class: "settings" });
  const errorBox = h("div");
  root.append(h("div", { class: "page-head" }, h("h1", {}, "Einstellungen")), errorBox, box);

  ctx.api("settings").then((S) => {
    box.append(
      upstreamCard(S), conditionalCard(S), blockingCard(S), cacheCard(S), accessCard(S),
      logCard(S), safeSearchCard(S), listsCard(S));
    if (!me.core_mode) box.append(accountCard());
  }, (e) => {
    if (!isAbort(e)) errorBox.replaceChildren(banner("error", "Die Einstellungen konnten nicht geladen werden.", e.message));
  });

  function upstreamCard(S) {
    const results = h("div", { "aria-live": "polite" });
    let ups, fallback, bootstrap;
    const testBtn = h("button", {
      type: "button",
      onclick: async () => {
        const all = [...new Set([...lines(ups.input.value), ...lines(fallback.input.value)])].slice(0, 20);
        if (!all.length) { results.replaceChildren(h("div", { class: "form-error" }, "Trage zuerst mindestens einen Upstream ein.")); return; }
        testBtn.disabled = true;
        results.replaceChildren(h("p", { class: "muted", style: "display:flex;gap:8px;align-items:center" }, h("span", { class: "spinner", "aria-hidden": "true" }), "Teste Upstreams …"));
        try {
          const res = await ctx.api("upstreams/test", { method: "POST", body: { upstreams: all, bootstrap: lines(bootstrap.input.value) } });
          results.replaceChildren(h("ul", { class: "test-results" }, (res.results || []).map((r) => h("li", {},
            h("span", { class: "dot " + (r.ok ? "good" : "bad"), "aria-hidden": "true" }),
            h("span", { class: "addr" }, r.upstream),
            h("span", { class: "res " + (r.ok ? "good-text" : "error-text") }, r.ok ? fmtMs(r.ms) : "Fehler"),
            !r.ok && r.error ? h("span", { class: "err" }, r.error) : null))));
        } catch (e) {
          if (!isAbort(e)) results.replaceChildren(h("div", { class: "form-error" }, e.message));
        } finally {
          testBtn.disabled = false;
        }
      },
    }, "Testen");
    return settingsCard(ctx, S, {
      title: "Upstream-DNS", wide: true,
      intro: "An diese Server schickt PK95 DNS alle Anfragen, die nicht blockiert oder aus dem Cache beantwortet werden.",
      build: (scope) => {
        ups = bindLines(scope, "upstreams", "Upstream-Server", { rows: 4, placeholder: "https://dns.quad9.net/dns-query\nquic://dns.adguard-dns.com\ntls://dns.quad9.net", hint: "Einer pro Zeile: https://…/dns-query (DNS over HTTPS), h3://…/dns-query (DoH über HTTP/3), quic://dns.adguard-dns.com (DNS over QUIC), tls://dns.quad9.net (DNS over TLS). Klartext (9.9.9.9, tcp://…) nur, wenn „Nur verschlüsselt“ aus ist." });
        fallback = bindLines(scope, "fallback", "Fallback-Server", { rows: 2, placeholder: "https://9.9.9.9/dns-query", hint: "Werden gefragt, wenn kein Upstream antwortet." });
        bootstrap = bindLines(scope, "bootstrap", "Bootstrap-DNS", { rows: 2, placeholder: "9.9.9.9", hint: "Nur IP-Adressen. Lösen nur die Namen der verschlüsselten Upstreams auf; die Zertifikatsprüfung schützt die Verbindung trotzdem. Leer = System-Resolver." });
        const encrypted = bindToggle(scope, "encrypted_only", "Nur verschlüsselte Upstreams", { hint: "Upstreams und Fallbacks müssen DoH, DoH3, DoQ oder DoT sprechen. Zertifikate werden immer geprüft. Bedingte Weiterleitung und private PTR-Anfragen ins LAN dürfen Klartext nutzen." });
        const mode = bindRadio(scope, "upstream_mode", "Abfragemodus", [
          ["load_balance", "Lastverteilung", "Wählt bevorzugt den schnellsten Upstream."],
          ["parallel", "Parallel", "Fragt alle gleichzeitig, die schnellste Antwort gewinnt."],
          ["sequential", "Nacheinander", "Fragt in der eingetragenen Reihenfolge."],
        ]);
        const timeout = bindNumber(scope, "upstream_timeout_ms", "Zeitlimit", { unit: "ms", min: 500, max: 30000, hint: "500 bis 30.000 Millisekunden" });
        const dnssec = bindToggle(scope, "dnssec", "DNSSEC anfordern", { hint: "Setzt das DO-Bit bei Anfragen an die Upstreams." });
        const noV6 = bindToggle(scope, "disable_ipv6", "IPv6-Adressen (AAAA) nicht ausliefern", { hint: "Hilft in Netzen ohne funktionierendes IPv6." });
        return {
          bindings: [ups, fallback, bootstrap, encrypted, mode, timeout, dnssec, noV6],
          nodes: [
            h("div", { class: "form-grid" }, ups.el, h("div", { class: "stack" }, fallback.el, bootstrap.el)),
            encrypted.el,
            h("div", { class: "form-grid" }, mode.el, h("div", { class: "stack" }, timeout.el, dnssec.el, noV6.el)),
            results,
          ],
          extra: testBtn,
        };
      },
    });
  }

  function conditionalCard(S) {
    return settingsCard(ctx, S, {
      title: "Bedingte Weiterleitung",
      intro: "Namen aus dem Heimnetz und Rückwärts-Anfragen für private Adressen an den Router statt ins Internet.",
      build: (scope) => {
        const cond = bindConditional(scope);
        const ptr = bindToggle(scope, "private_ptr", "Private Rückwärts-Anfragen im Netz behalten", { hint: "PTR-Anfragen für private Adressen gehen nie an öffentliche Upstreams." });
        const priv = bindLines(scope, "private_upstreams", "Upstreams für private Rückwärts-Anfragen", { rows: 2, placeholder: "192.168.178.1", hint: "Leer: solche Anfragen werden mit NXDOMAIN beantwortet." });
        return { bindings: [cond, ptr, priv], nodes: [cond.el, ptr.el, priv.el] };
      },
    });
  }

  function blockingCard(S) {
    let mode, v4, v6;
    const customBox = h("div", { class: "form-grid" });
    return settingsCard(ctx, S, {
      title: "Blockieren",
      intro: "So antwortet PK95 DNS auf gesperrte Domains.",
      build: (scope) => {
        const sync = () => { customBox.hidden = mode.get() !== "custom_ip"; };
        mode = bindRadio(scope, "blocking_mode", "Antwort", [
          ["null_ip", "Null-IP", "0.0.0.0 bzw. :: – empfohlen, Geräte geben sofort auf."],
          ["nxdomain", "NXDOMAIN", "Die Domain existiert angeblich nicht."],
          ["refused", "REFUSED", "Die Anfrage wird abgelehnt."],
          ["custom_ip", "Eigene IP-Adresse", "Zum Beispiel ein Server mit einer Hinweisseite."],
        ], { onchange: () => sync() });
        v4 = bindText(scope, "blocking_ipv4", "IPv4-Adresse", { placeholder: "192.168.1.2" });
        v6 = bindText(scope, "blocking_ipv6", "IPv6-Adresse", { placeholder: "fd00::2" });
        customBox.append(v4.el, v6.el);
        const ttl = bindNumber(scope, "blocked_ttl", "Gültigkeit der Antwort", { unit: "Sekunden", min: 0, max: 86400, hint: "Wie lange Geräte die gesperrte Antwort zwischenspeichern." });
        return { bindings: [mode, v4, v6, ttl], nodes: [mode.el, customBox, ttl.el], after: sync };
      },
    });
  }

  function cacheCard(S) {
    const info = h("p", { class: "small muted" });
    const loadInfo = () => ctx.api("status").then((st) => {
      updateSideStatus(st);
      const c = st.cache || {};
      const rate = pct(c.hits || 0, (c.hits || 0) + (c.misses || 0));
      info.textContent = c.enabled === false ? "Der Cache ist ausgeschaltet."
        : `${plural(c.entries || 0, "Eintrag", "Einträge")} im Cache, Trefferquote ${fmtPct(rate)}.`;
    }, () => {});
    const clearBtn = h("button", {
      type: "button",
      onclick: async () => {
        clearBtn.disabled = true;
        try {
          await ctx.api("cache", { method: "DELETE" });
          toast("Der Cache ist leer.");
          loadInfo();
        } catch (e) { toastError(e); }
        clearBtn.disabled = false;
      },
    }, "Cache leeren");
    loadInfo();
    return settingsCard(ctx, S, {
      title: "Cache",
      intro: "Gespeicherte Antworten machen wiederholte Anfragen schneller.",
      build: (scope) => {
        const on = bindToggle(scope, "cache_enabled", "Cache verwenden");
        const size = bindNumber(scope, "cache_size", "Größe", { unit: "Einträge", min: 0, max: 1000000 });
        const min = bindNumber(scope, "cache_min_ttl", "Mindest-TTL", { unit: "s", min: 0, max: 3600 });
        const max = bindNumber(scope, "cache_max_ttl", "Höchst-TTL", { unit: "s", min: 0, max: 604800, hint: "0 = keine Grenze" });
        return { bindings: [on, size, min, max], nodes: [on.el, size.el, h("div", { class: "form-grid-3" }, min.el, max.el), info], extra: clearBtn };
      },
    });
  }

  function accessCard(S) {
    const warn = banner("error", "Offener Resolver!", "Ohne erlaubte Clients darf jeder fragen. Ist PK95 DNS aus dem Internet erreichbar, kann es für Angriffe missbraucht werden.");
    return settingsCard(ctx, S, {
      title: "Zugriff",
      intro: "Wer PK95 DNS fragen darf.",
      build: (scope) => {
        const allowed = bindLines(scope, "allowed_clients", "Erlaubte Clients", { rows: 5, hint: "IP-Adressen oder Netze (CIDR), eine pro Zeile. Leer = alle.", oninput: () => sync() });
        const denied = bindLines(scope, "disallowed_clients", "Gesperrte Clients", { rows: 2, hint: "Werden immer abgewiesen." });
        const rate = bindNumber(scope, "ratelimit", "Ratenlimit", { unit: "Anfragen pro Sekunde und Client", min: 0, max: 100000, hint: "0 = kein Limit" });
        const any = bindToggle(scope, "refuse_any", "ANY-Anfragen ablehnen", { hint: "Schützt vor Verstärkungsangriffen." });
        const sync = () => { warn.hidden = lines(allowed.input.value).length > 0; };
        return { bindings: [allowed, denied, rate, any], nodes: [warn, allowed.el, denied.el, rate.el, any.el], after: sync };
      },
    });
  }

  function logCard(S) {
    const resetBtn = h("button", {
      type: "button", class: "danger",
      onclick: () => confirmDialog({
        title: "Statistik zurücksetzen?",
        text: "Alle Zähler und Top-Listen werden gelöscht. Das Abfrageprotokoll bleibt erhalten.",
        confirm: "Zurücksetzen",
        action: async () => {
          await ctx.api("stats", { method: "DELETE" });
          toast("Die Statistik wurde zurückgesetzt.");
        },
      }),
    }, "Statistik zurücksetzen");
    return settingsCard(ctx, S, {
      title: "Abfrageprotokoll & Statistik",
      build: (scope) => {
        const on = bindToggle(scope, "querylog_enabled", "Abfragen protokollieren");
        const hours = bindSelect(scope, "querylog_hours", "Protokoll aufbewahren", [
          [6, "6 Stunden"], [24, "1 Tag"], [72, "3 Tage"], [168, "7 Tage"], [720, "30 Tage"], [2160, "90 Tage"],
        ], { custom: (v) => plural(v, "Stunde", "Stunden") });
        const anon = bindToggle(scope, "anonymize_ip", "IP-Adressen anonymisieren", { hint: "Speichert IPv4 ohne letztes Byte und IPv6 gekürzt auf /48." });
        const days = bindSelect(scope, "stats_days", "Statistik aufbewahren", [
          [1, "1 Tag"], [7, "7 Tage"], [14, "14 Tage"], [30, "30 Tage"], [60, "60 Tage"], [90, "90 Tage"],
        ], { custom: (v) => plural(v, "Tag", "Tage") });
        return { bindings: [on, hours, anon, days], nodes: [on.el, hours.el, anon.el, days.el], extra: resetBtn };
      },
    });
  }

  function safeSearchCard(S) {
    return settingsCard(ctx, S, {
      title: "SafeSearch",
      intro: "Leitet Suchmaschinen und YouTube auf ihre jugendfreie Variante um.",
      build: (scope) => {
        const ss = bindSafeSearch(scope);
        return { bindings: [ss], nodes: [ss.el] };
      },
    });
  }

  function listsCard(S) {
    return settingsCard(ctx, S, {
      title: "Blocklisten-Aktualisierung",
      build: (scope) => {
        const every = bindSelect(scope, "lists_update_hours", "Listen automatisch aktualisieren", [
          [0, "Nie (nur von Hand)"], [1, "Jede Stunde"], [6, "Alle 6 Stunden"], [12, "Alle 12 Stunden"], [24, "Täglich"], [72, "Alle 3 Tage"], [168, "Wöchentlich"],
        ], { custom: (v) => `Alle ${v} Stunden`, hint: "Unveränderte Listen werden dabei nicht erneut heruntergeladen." });
        return { bindings: [every], nodes: [every.el] };
      },
    });
  }

  function accountCard() {
    const general = h("div", { class: "form-error", role: "alert", hidden: true });
    const scope = errorScope(general);
    const cur = h("input", { type: "password", autocomplete: "current-password", required: true });
    const neu = h("input", { type: "password", autocomplete: "new-password", required: true, minLength: 12 });
    const rep = h("input", { type: "password", autocomplete: "new-password", required: true });
    const save = h("button", { type: "submit", class: "primary" }, "Passwort ändern");
    const form = h("form", {
      noValidate: true,
      onsubmit: async (e) => {
        e.preventDefault();
        scope.clear();
        const local = {};
        if (!cur.value) local.current = "Bitte gib dein aktuelles Passwort ein.";
        if (neu.value.length < 12) local.new = "Das neue Passwort braucht mindestens 12 Zeichen.";
        else if (neu.value !== rep.value) local.repeat = "Die beiden Passwörter stimmen nicht überein.";
        if (Object.keys(local).length) { scope.show({ fields: local, message: "" }); return; }
        save.disabled = true;
        try {
          await ctx.api("password", { method: "POST", body: { current: cur.value, new: neu.value } });
          cur.value = neu.value = rep.value = "";
          toast("Dein Passwort wurde geändert.");
        } catch (ex) {
          if (!isAbort(ex)) scope.show(ex);
        } finally {
          save.disabled = false;
        }
      },
    },
      general,
      h("input", { type: "text", autocomplete: "username", value: me.username, hidden: true, readOnly: true, "aria-hidden": "true", tabIndex: -1 }),
      field(scope, "current", "Aktuelles Passwort", cur),
      field(scope, "new", "Neues Passwort", neu, { hint: "Mindestens 12 Zeichen." }),
      field(scope, "repeat", "Neues Passwort wiederholen", rep),
      h("div", { class: "form-foot" }, h("span", { class: "spacer" }), save));
    return h("section", { class: "card" }, h("h2", {}, "Konto"), h("p", { class: "card-intro" }, `Angemeldet als ${me.username}.`), form);
  }
};

// --- Start -----------------------------------------------------------------

start();
