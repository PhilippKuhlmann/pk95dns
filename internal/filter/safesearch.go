package filter

import "pk95dns/internal/config"

type safeEngine uint8

const (
	ssGoogle safeEngine = iota + 1
	ssBing
	ssDuckDuckGo
	ssYouTube
	ssYandex
	ssPixabay
)

type safeTarget struct {
	engine safeEngine
	target string
}

// Safe hosts the search engines answer with their restricted mode.
const (
	safeGoogle     = "forcesafesearch.google.com"
	safeBing       = "strict.bing.com"
	safeDuckDuckGo = "safe.duckduckgo.com"
	safeYouTube    = "restrictmoderate.youtube.com"
	safeYandex     = "familysearch.yandex.ru"
	safePixabay    = "safesearch.pixabay.com"
)

// googleTLDs are the country domains of Google search (google.com/supported_domains).
var googleTLDs = []string{
	"com", "ad", "ae", "com.af", "com.ag", "al", "am", "co.ao", "com.ar", "as", "at", "com.au",
	"az", "ba", "com.bd", "be", "bf", "bg", "com.bh", "bi", "bj", "com.bn", "com.bo", "com.br",
	"bs", "bt", "co.bw", "by", "com.bz", "ca", "cat", "cd", "cf", "cg", "ch", "ci", "co.ck", "cl",
	"cm", "cn", "com.co", "co.cr", "com.cu", "cv", "com.cy", "cz", "de", "dj", "dk", "dm",
	"com.do", "dz", "com.ec", "ee", "com.eg", "es", "com.et", "fi", "com.fj", "fm", "fr", "ga",
	"ge", "gg", "com.gh", "com.gi", "gl", "gm", "gr", "com.gt", "gy", "com.hk", "hn", "hr", "ht",
	"hu", "co.id", "ie", "co.il", "im", "co.in", "iq", "is", "it", "je", "com.jm", "jo", "co.jp",
	"co.ke", "com.kh", "ki", "kg", "co.kr", "com.kw", "kz", "la", "com.lb", "li", "lk", "co.ls",
	"lt", "lu", "lv", "com.ly", "co.ma", "md", "me", "mg", "mk", "ml", "com.mm", "mn", "com.mt",
	"mu", "mv", "mw", "com.mx", "com.my", "co.mz", "com.na", "com.ng", "com.ni", "ne", "nl", "no",
	"com.np", "nr", "nu", "co.nz", "com.om", "com.pa", "com.pe", "com.pg", "com.ph", "com.pk",
	"pl", "pn", "com.pr", "ps", "pt", "com.py", "com.qa", "ro", "rs", "ru", "rw", "com.sa",
	"com.sb", "sc", "se", "com.sg", "sh", "si", "sk", "com.sl", "sn", "so", "sm", "sr", "st",
	"com.sv", "td", "tg", "co.th", "com.tj", "tl", "tm", "tn", "to", "com.tr", "tt", "com.tw",
	"co.tz", "com.ua", "co.ug", "co.uk", "com.uy", "co.uz", "com.vc", "co.ve", "co.vi", "com.vn",
	"vu", "ws", "co.za", "co.zm", "co.zw",
}

var yandexTLDs = []string{"ru", "com", "com.tr", "ua", "by", "kz"}

var safeSearchTable = buildSafeSearchTable()

func buildSafeSearchTable() map[string]safeTarget {
	t := make(map[string]safeTarget, 2*len(googleTLDs)+40)
	add := func(engine safeEngine, target string, names ...string) {
		for _, n := range names {
			t[n] = safeTarget{engine: engine, target: target}
		}
	}
	for _, tld := range googleTLDs {
		add(ssGoogle, safeGoogle, "google."+tld, "www.google."+tld)
	}
	add(ssBing, safeBing, "bing.com", "www.bing.com")
	add(ssDuckDuckGo, safeDuckDuckGo, "duckduckgo.com", "www.duckduckgo.com", "start.duckduckgo.com")
	add(ssYouTube, safeYouTube, "www.youtube.com", "m.youtube.com", "youtubei.googleapis.com",
		"youtube.googleapis.com", "www.youtube-nocookie.com")
	for _, tld := range yandexTLDs {
		add(ssYandex, safeYandex, "yandex."+tld, "www.yandex."+tld)
	}
	add(ssPixabay, safePixabay, "pixabay.com", "www.pixabay.com")
	return t
}

// SafeSearchTarget returns the host a name is rewritten to when SafeSearch is enabled for its
// engine (docs/design.md → SafeSearch). opts.Enabled false → ("", false).
func SafeSearchTarget(name string, opts config.SafeSearch) (string, bool) {
	if !opts.Enabled {
		return "", false
	}
	t, ok := safeSearchTable[NormalizeName(name)]
	if !ok {
		return "", false
	}
	var on bool
	switch t.engine {
	case ssGoogle:
		on = opts.Google
	case ssBing:
		on = opts.Bing
	case ssDuckDuckGo:
		on = opts.DuckDuckGo
	case ssYouTube:
		on = opts.YouTube
	case ssYandex:
		on = opts.Yandex
	case ssPixabay:
		on = opts.Pixabay
	}
	if !on {
		return "", false
	}
	return t.target, true
}
