package filter

import (
	"slices"
	"strings"
	"testing"

	"github.com/miekg/dns"

	"pk95dns/internal/config"
)

func TestServicesCatalog(t *testing.T) {
	svcs := Services()
	required := []string{
		"youtube", "tiktok", "instagram", "facebook", "whatsapp", "twitter", "snapchat", "pinterest",
		"reddit", "linkedin", "discord", "telegram", "signal", "netflix", "twitch", "disneyplus",
		"primevideo", "spotify", "steam", "epicgames", "roblox", "minecraft", "playstation", "xboxlive",
		"amazon", "ebay", "temu", "aliexpress", "chatgpt", "tinder", "9gag", "vk",
	}
	for _, id := range required {
		if !KnownService(id) {
			t.Errorf("service %q missing", id)
		}
	}
	if KnownService("nope") || KnownService("") {
		t.Error("KnownService accepts unknown ids")
	}

	ids := map[string]bool{}
	domains := map[string]string{}
	for i, s := range svcs {
		if ids[s.ID] {
			t.Errorf("duplicate id %q", s.ID)
		}
		ids[s.ID] = true
		if s.Name == "" || !slices.Contains(serviceGroups, s.Group) {
			t.Errorf("%s: name %q group %q", s.ID, s.Name, s.Group)
		}
		if len(s.Rules) == 0 {
			t.Errorf("%s: no rules", s.ID)
		}
		for _, r := range s.Rules {
			d, ok := strings.CutPrefix(r, "||")
			d, ok2 := strings.CutSuffix(d, "^")
			if !ok || !ok2 || !ValidDomain(d, false) {
				t.Errorf("%s: invalid rule %q", s.ID, r)
			}
			if other, dup := domains[d]; dup {
				t.Errorf("domain %s in %s and %s", d, other, s.ID)
			}
			domains[d] = s.ID
		}
		if i > 0 {
			prev := svcs[i-1]
			gp, gs := slices.Index(serviceGroups, prev.Group), slices.Index(serviceGroups, s.Group)
			if gp > gs || gp == gs && strings.ToLower(prev.Name) > strings.ToLower(s.Name) {
				t.Errorf("order: %s before %s", prev.ID, s.ID)
			}
		}
	}

	// Services returns a copy.
	svcs[0].Rules[0] = "changed"
	svcs[0].Name = "changed"
	if again := Services(); again[0].Rules[0] == "changed" || again[0].Name == "changed" {
		t.Error("Services returns shared data")
	}
}

func TestServiceDomains(t *testing.T) {
	want := map[string][]string{
		"youtube": {"youtube.com", "youtu.be", "ytimg.com", "googlevideo.com", "youtube-nocookie.com",
			"youtubei.googleapis.com", "youtube.googleapis.com", "yt3.ggpht.com", "yt.be"},
		"tiktok":   {"tiktok.com", "tiktokv.com", "tiktokcdn.com", "byteoversea.com", "ibytedtos.com", "musical.ly"},
		"twitter":  {"twitter.com", "x.com", "twimg.com", "t.co"},
		"whatsapp": {"whatsapp.com", "whatsapp.net", "wa.me"},
		"netflix":  {"netflix.com", "nflxvideo.net", "nflximg.net"},
	}
	byID := map[string]Service{}
	for _, s := range Services() {
		byID[s.ID] = s
	}
	for id, doms := range want {
		for _, d := range doms {
			if !slices.Contains(byID[id].Rules, "||"+d+"^") {
				t.Errorf("%s: missing %s", id, d)
			}
		}
	}
}

func TestServiceBlocking(t *testing.T) {
	e := NewEngine()
	tests := []struct {
		name string
		svc  []string
		want Result
	}{
		{"www.youtube.com", []string{"youtube"}, Result{Action: Block, Reason: ReasonService, Rule: "||youtube.com^", Service: "youtube"}},
		{"i.ytimg.com", []string{"tiktok", "youtube"}, Result{Action: Block, Reason: ReasonService, Rule: "||ytimg.com^", Service: "youtube"}},
		// the most specific catalog domain wins
		{"yt3.ggpht.com", []string{"youtube"}, Result{Action: Block, Reason: ReasonService, Rule: "||yt3.ggpht.com^", Service: "youtube"}},
		{"ggpht.com", []string{"youtube"}, Result{}},
		{"v16.tiktokcdn.com", []string{"tiktok"}, Result{Action: Block, Reason: ReasonService, Rule: "||tiktokcdn.com^", Service: "tiktok"}},
		{"www.tiktok.com", []string{"youtube"}, Result{}},
		{"www.tiktok.com", nil, Result{}},
		{"notyoutube.com", []string{"youtube"}, Result{}},
		{"gemini.google.com", []string{"gemini"}, Result{Action: Block, Reason: ReasonService, Rule: "||gemini.google.com^", Service: "gemini"}},
		{"www.google.com", []string{"gemini"}, Result{}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			checkResult(t, e.Check(Request{Name: tt.name, QType: dns.TypeA, Services: tt.svc}), tt.want)
		})
	}
}

func TestSafeSearchTarget(t *testing.T) {
	tests := []struct {
		name   string
		opts   config.SafeSearch
		target string
	}{
		{"www.google.com", safeAll, "forcesafesearch.google.com"},
		{"google.com", safeAll, "forcesafesearch.google.com"},
		{"www.google.de", safeAll, "forcesafesearch.google.com"},
		{"google.de", safeAll, "forcesafesearch.google.com"},
		{"www.google.co.uk", safeAll, "forcesafesearch.google.com"},
		{"google.com.au", safeAll, "forcesafesearch.google.com"},
		{"www.google.at", safeAll, "forcesafesearch.google.com"},
		{"www.google.ch", safeAll, "forcesafesearch.google.com"},
		{"WWW.Google.FR.", safeAll, "forcesafesearch.google.com"},
		{"mail.google.com", safeAll, ""},
		{"forcesafesearch.google.com", safeAll, ""},
		{"www.google.invalid", safeAll, ""},
		{"www.bing.com", safeAll, "strict.bing.com"},
		{"bing.com", safeAll, "strict.bing.com"},
		{"duckduckgo.com", safeAll, "safe.duckduckgo.com"},
		{"www.duckduckgo.com", safeAll, "safe.duckduckgo.com"},
		{"start.duckduckgo.com", safeAll, "safe.duckduckgo.com"},
		{"www.youtube.com", safeAll, "restrictmoderate.youtube.com"},
		{"m.youtube.com", safeAll, "restrictmoderate.youtube.com"},
		{"youtubei.googleapis.com", safeAll, "restrictmoderate.youtube.com"},
		{"youtube.googleapis.com", safeAll, "restrictmoderate.youtube.com"},
		{"www.youtube-nocookie.com", safeAll, "restrictmoderate.youtube.com"},
		{"youtube.com", safeAll, ""},
		{"yandex.ru", safeAll, "familysearch.yandex.ru"},
		{"www.yandex.com.tr", safeAll, "familysearch.yandex.ru"},
		{"yandex.kz", safeAll, "familysearch.yandex.ru"},
		{"www.yandex.by", safeAll, "familysearch.yandex.ru"},
		{"yandex.ua", safeAll, "familysearch.yandex.ru"},
		{"pixabay.com", safeAll, "safesearch.pixabay.com"},
		{"www.pixabay.com", safeAll, "safesearch.pixabay.com"},
		// master switch and per-engine flags
		{"www.google.com", config.SafeSearch{Google: true, Bing: true}, ""},
		{"www.google.com", config.SafeSearch{Enabled: true}, ""},
		{"www.google.com", config.SafeSearch{Enabled: true, Google: true}, "forcesafesearch.google.com"},
		{"www.bing.com", config.SafeSearch{Enabled: true, Google: true}, ""},
		{"www.bing.com", config.SafeSearch{Enabled: true, Bing: true}, "strict.bing.com"},
		{"duckduckgo.com", config.SafeSearch{Enabled: true, Google: true}, ""},
		{"duckduckgo.com", config.SafeSearch{Enabled: true, DuckDuckGo: true}, "safe.duckduckgo.com"},
		{"www.youtube.com", config.SafeSearch{Enabled: true, Google: true}, ""},
		{"www.youtube.com", config.SafeSearch{Enabled: true, YouTube: true}, "restrictmoderate.youtube.com"},
		{"yandex.ru", config.SafeSearch{Enabled: true, Google: true}, ""},
		{"yandex.ru", config.SafeSearch{Enabled: true, Yandex: true}, "familysearch.yandex.ru"},
		{"pixabay.com", config.SafeSearch{Enabled: true, Google: true}, ""},
		{"pixabay.com", config.SafeSearch{Enabled: true, Pixabay: true}, "safesearch.pixabay.com"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := SafeSearchTarget(tt.name, tt.opts)
			if got != tt.target || ok != (tt.target != "") {
				t.Errorf("got %q %v, want %q", got, ok, tt.target)
			}
		})
	}
	if n := len(googleTLDs); n < 180 {
		t.Errorf("only %d Google TLDs", n)
	}
}

func TestNormalizeName(t *testing.T) {
	tests := map[string]string{
		"example.org":   "example.org",
		"Example.ORG.":  "example.org",
		"example.org.":  "example.org",
		".":             "",
		"":              "",
		"_DMARC.x.Org.": "_dmarc.x.org",
	}
	for in, want := range tests {
		if got := NormalizeName(in); got != want {
			t.Errorf("NormalizeName(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestValidDomain(t *testing.T) {
	long63 := strings.Repeat("a", 63)
	tests := []struct {
		name     string
		wildcard bool
		want     bool
	}{
		{"example.org", false, true},
		{"nas", false, true},
		{"_dmarc.example.org", false, true},
		{"_sip._tcp.example.org", false, true},
		{"xn--bcher-kva.example", false, true},
		{"a-b.c", false, true},
		{"1.2.3.4", false, true},
		{long63 + ".org", false, true},
		{long63 + "a.org", false, false},
		{strings.Repeat("a.", 126) + "a", false, true}, // 253 chars
		{strings.Repeat("a.", 127) + "a", false, false},
		{"", false, false},
		{".", false, false},
		{"example.org.", false, false},
		{".example.org", false, false},
		{"a..b", false, false},
		{"-a.org", false, false},
		{"a-.org", false, false},
		{"Example.org", false, false},
		{"bü.de", false, false},
		{"a b.org", false, false},
		{"*.example.org", false, false},
		{"*.example.org", true, true},
		{"*.", true, false},
		{"*", true, false},
		{"a.*.org", true, false},
		{"**.org", true, false},
	}
	for _, tt := range tests {
		if got := ValidDomain(tt.name, tt.wildcard); got != tt.want {
			t.Errorf("ValidDomain(%q, %v) = %v, want %v", tt.name, tt.wildcard, got, tt.want)
		}
	}
}
