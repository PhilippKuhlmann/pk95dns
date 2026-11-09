package lists

// catalog is the list of well-known block and allow lists (GET /api/lists/catalog).
var catalog = []CatalogEntry{
	{
		Name:        "AdGuard DNS filter",
		URL:         "https://adguardteam.github.io/HostlistsRegistry/assets/filter_1.txt",
		Kind:        "block",
		Description: "Standardliste von AdGuard: Werbung, Tracking und Analyse-Dienste. Gut gepflegt, kaum Fehlalarme.",
	},
	{
		Name:        "OISD Small",
		URL:         "https://small.oisd.nl/",
		Kind:        "block",
		Description: "Kompakte Liste gegen Werbung, Tracking und Schadsoftware. Ziel: nichts kaputt machen.",
	},
	{
		Name:        "OISD Big",
		URL:         "https://big.oisd.nl/",
		Kind:        "block",
		Description: "Große Fassung von OISD mit deutlich mehr Domains. Sehr wenige Fehlalarme trotz hoher Abdeckung.",
	},
	{
		Name:        "StevenBlack Unified Hosts",
		URL:         "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts",
		Kind:        "block",
		Description: "Bekannte Hosts-Datei aus mehreren Quellen: Werbung und Schadsoftware.",
	},
	{
		Name:        "HaGeZi Light",
		URL:         "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/light.txt",
		Kind:        "block",
		Description: "Leichte HaGeZi-Liste: Werbung, Tracking, Schadsoftware. Für Geräte, auf denen nichts stören darf.",
	},
	{
		Name:        "HaGeZi Multi Normal",
		URL:         "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/multi.txt",
		Kind:        "block",
		Description: "Ausgewogene Allround-Liste von HaGeZi: Werbung, Tracking, Metriken, Phishing, Schadsoftware.",
	},
	{
		Name:        "HaGeZi Pro",
		URL:         "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/pro.txt",
		Kind:        "block",
		Description: "Strengere HaGeZi-Liste mit mehr Tracking-Domains. Gelegentlich muss etwas freigegeben werden.",
	},
	{
		Name:        "HaGeZi Threat Intelligence Feeds",
		URL:         "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/tif.txt",
		Kind:        "block",
		Description: "Bedrohungsdaten: Schadsoftware, Phishing, Betrug, Krypto-Mining und Command-and-Control-Server.",
	},
	{
		Name:        "1Hosts Lite",
		URL:         "https://adguardteam.github.io/HostlistsRegistry/assets/filter_24.txt",
		Kind:        "block",
		Description: "Ausgewogene Liste gegen Werbung, Tracking und Schadsoftware, ohne den Alltag zu stören.",
	},
	{
		Name:        "AdAway",
		URL:         "https://adaway.org/hosts.txt",
		Kind:        "block",
		Description: "Hosts-Datei von AdAway, ursprünglich für Werbung in mobilen Apps.",
	},
	{
		Name:        "Phishing Army",
		URL:         "https://phishing.army/download/phishing_army_blocklist.txt",
		Kind:        "block",
		Description: "Bekannte Phishing-Seiten aus mehreren Quellen (PhishTank, OpenPhish u. a.).",
	},
	{
		Name:        "Dan Pollock (someonewhocares)",
		URL:         "https://someonewhocares.org/hosts/zero/hosts",
		Kind:        "block",
		Description: "Seit vielen Jahren gepflegte Hosts-Datei gegen Werbung, Tracking und Schadsoftware.",
	},
	{
		Name:        "HaGeZi Allowlist Referral",
		URL:         "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/whitelist-referral.txt",
		Kind:        "allow",
		Description: "Freigabeliste: lässt Affiliate- und Weiterleitungslinks aus Mails und Suchergebnissen zu, die strenge Listen sonst sperren.",
	},
}
