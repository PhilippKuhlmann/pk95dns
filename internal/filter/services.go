package filter

import (
	"slices"
	"strings"
)

// Service is one entry of the blocked services catalog.
type Service struct {
	ID    string   `json:"id"`
	Name  string   `json:"name"`
	Group string   `json:"group"` // social, messenger, video, music, gaming, shopping, ai, other
	Rules []string `json:"-"`     // "||domain^" rules
}

// serviceGroups is the display order of the groups (docs/api.md → Blocked services).
var serviceGroups = []string{"social", "messenger", "video", "music", "gaming", "shopping", "ai", "other"}

// serviceDef is the source form of the catalog: domains, each blocked with all subdomains.
type serviceDef struct {
	id, name, group string
	domains         []string
}

var serviceDefs = []serviceDef{
	// social
	{"facebook", "Facebook", "social", []string{
		"facebook.com", "facebook.net", "facebook.de", "fb.com", "fb.me", "fb.gg", "fb.watch",
		"fbcdn.net", "fbcdn.com", "fbsbx.com", "fbpigeon.com", "messenger.com",
		"m.me", "accountkit.com", "facebookmail.com",
	}},
	{"instagram", "Instagram", "social", []string{
		"instagram.com", "cdninstagram.com", "instagr.am", "ig.me", "igcdn.com", "igsonar.com",
	}},
	{"tiktok", "TikTok", "social", []string{
		"tiktok.com", "tiktokv.com", "tiktokv.us", "tiktokv.eu", "tiktokw.us", "tiktokcdn.com",
		"tiktokcdn-us.com", "tiktokcdn-eu.com", "tiktokd.net", "tiktokd.org",
		"tik-tokapi.com", "byteoversea.com", "byteoversea.net", "ibytedtos.com", "ibyteimg.com",
		"ipstatp.com", "muscdn.com", "musical.ly", "ttwstatic.com",
	}},
	{"twitter", "X (Twitter)", "social", []string{
		"x.com", "twitter.com", "twimg.com", "t.co", "twttr.com", "twitter.co", "twtrdns.net",
		"ads-twitter.com", "twitpic.com", "tweetdeck.com", "pscp.tv", "periscope.tv",
		"twitterinc.com", "twitterstat.us",
	}},
	{"snapchat", "Snapchat", "social", []string{
		"snapchat.com", "snap.com", "snapads.com", "snapkit.com", "snapkit.co", "sc-cdn.net",
		"sc-static.net", "sc-gw.com", "snap-dev.net", "bitmoji.com", "feelinsonice-hrd.appspot.com",
		"feelinsonice.appspot.com",
	}},
	{"pinterest", "Pinterest", "social", []string{
		"pinterest.com", "pinterest.de", "pinterest.at", "pinterest.ch", "pinterest.co.uk",
		"pinterest.fr", "pinterest.es", "pinterest.it", "pinterest.nl", "pinterest.ca",
		"pinterest.com.au", "pinterest.jp", "pinimg.com", "pin.it",
	}},
	{"reddit", "Reddit", "social", []string{
		"reddit.com", "redd.it", "redditmedia.com", "redditstatic.com", "reddituploads.com",
		"redditblog.com", "redditinc.com", "redditspace.com", "reddit.app.link", "redditmail.com",
	}},
	{"linkedin", "LinkedIn", "social", []string{
		"linkedin.com", "licdn.com", "lnkd.in", "linkedin.cn",
	}},
	{"tumblr", "Tumblr", "social", []string{
		"tumblr.com", "tmblr.co",
	}},
	{"threads", "Threads", "social", []string{
		"threads.net", "threads.com",
	}},
	{"bluesky", "Bluesky", "social", []string{
		"bsky.app", "bsky.social", "bsky.network", "blueskyweb.xyz",
	}},
	{"vk", "VK", "social", []string{
		"vk.com", "vk.ru", "vk.me", "vk.cc", "vk-cdn.net", "vkuser.net", "vkuseraudio.net",
		"vkuservideo.net", "vkontakte.ru", "userapi.com",
	}},
	// messenger
	{"whatsapp", "WhatsApp", "messenger", []string{
		"whatsapp.com", "whatsapp.net", "wa.me", "whatsapp.biz",
	}},
	{"telegram", "Telegram", "messenger", []string{
		"telegram.org", "telegram.me", "telegram.dog", "t.me", "telegra.ph", "telesco.pe",
		"tdesktop.com", "cdn-telegram.org", "graph.org", "fragment.com",
	}},
	{"signal", "Signal", "messenger", []string{
		"signal.org", "signal.art", "signal.me", "signal.group", "signal.link", "whispersystems.org",
	}},
	{"discord", "Discord", "messenger", []string{
		"discord.com", "discord.gg", "discord.co", "discord.gift", "discord.media", "discord.new",
		"discord.dev", "discordapp.com", "discordapp.net", "discordcdn.com", "discordstatus.com",
		"dis.gd",
	}},
	{"skype", "Skype", "messenger", []string{
		"skype.com", "skype.net", "skypeassets.com", "skypeassets.net",
	}},
	{"viber", "Viber", "messenger", []string{
		"viber.com",
	}},
	{"wechat", "WeChat", "messenger", []string{
		"wechat.com", "weixin.qq.com", "wx.qq.com", "wechatpay.com",
	}},
	// video
	{"youtube", "YouTube", "video", []string{
		"youtube.com", "youtu.be", "yt.be", "ytimg.com", "googlevideo.com", "youtube-nocookie.com",
		"youtubei.googleapis.com", "youtube.googleapis.com", "youtubeembeddedplayer.googleapis.com",
		"yt3.ggpht.com", "yt4.ggpht.com", "yt3.googleusercontent.com", "youtube-ui.l.google.com",
		"wide-youtube.l.google.com", "youtubekids.com", "youtubegaming.com", "youtubeeducation.com",
		"youtube.de", "youtube.at", "youtube.ch", "youtube.co.uk", "withyoutube.com",
		"youtubego.com",
	}},
	{"netflix", "Netflix", "video", []string{
		"netflix.com", "netflix.net", "nflxext.com", "nflximg.com", "nflximg.net", "nflxso.net",
		"nflxvideo.net", "nflxsearch.net", "netflixdnstest0.com", "netflixdnstest1.com",
		"netflixdnstest2.com", "netflixdnstest3.com", "netflixdnstest4.com", "netflixdnstest5.com",
		"netflixdnstest6.com", "netflixdnstest7.com", "netflixdnstest8.com", "netflixdnstest9.com",
		"netflixdnstest10.com",
	}},
	{"twitch", "Twitch", "video", []string{
		"twitch.tv", "twitch.a2z.com", "ttvnw.net", "jtvnw.net", "twitchcdn.net", "twitchsvc.net",
		"ext-twitch.tv", "live-video.net", "twitchapps.com",
	}},
	{"disneyplus", "Disney+", "video", []string{
		"disneyplus.com", "disney-plus.net", "disneystreaming.com", "dssott.com", "bamgrid.com",
		"disneyplus.bn5x.net", "disney.demdex.net",
	}},
	{"primevideo", "Prime Video", "video", []string{
		"primevideo.com", "amazonvideo.com", "aiv-cdn.net", "aiv-delivery.net", "pv-cdn.net",
		"atv-ps.amazon.com", "atv-ps-eu.amazon.com", "atv-ext.amazon.com", "atv-ext-eu.amazon.com",
	}},
	{"vimeo", "Vimeo", "video", []string{
		"vimeo.com", "vimeocdn.com", "vimeo.tv", "livestream.com",
	}},
	{"dailymotion", "Dailymotion", "video", []string{
		"dailymotion.com", "dmcdn.net", "dm-event.net", "dmxleo.com",
	}},
	// music
	{"spotify", "Spotify", "music", []string{
		"spotify.com", "spotify.net", "scdn.co", "spotifycdn.com", "spotifycdn.net", "spoti.fi",
		"spotify.link", "pscdn.co", "spotilocal.com", "spotifycharts.com", "spotify.design",
		"audio-ak-spotify-com.akamaized.net", "heads-ak-spotify-com.akamaized.net",
	}},
	{"deezer", "Deezer", "music", []string{
		"deezer.com", "deezer.page.link", "dzcdn.net",
	}},
	{"soundcloud", "SoundCloud", "music", []string{
		"soundcloud.com", "sndcdn.com",
	}},
	// gaming
	{"steam", "Steam", "gaming", []string{
		"steampowered.com", "steamcommunity.com", "steamstatic.com", "steamcontent.com",
		"steamserver.net", "steamgames.com", "steamusercontent.com", "steam-chat.com",
		"steamcdn-a.akamaihd.net", "valvesoftware.com", "s.team",
	}},
	{"epicgames", "Epic Games", "gaming", []string{
		"epicgames.com", "epicgames.dev", "unrealengine.com", "fortnite.com",
		"epicgames-download1.akamaized.net",
	}},
	{"roblox", "Roblox", "gaming", []string{
		"roblox.com", "rbxcdn.com", "rbx.com", "robloxlabs.com", "roblox.qq.com",
	}},
	{"minecraft", "Minecraft", "gaming", []string{
		"minecraft.net", "mojang.com", "minecraftservices.com", "minecraft-services.net",
		"minecraftshop.com",
	}},
	{"playstation", "PlayStation Network", "gaming", []string{
		"playstation.com", "playstation.net", "playstationnetwork.com", "sonyentertainmentnetwork.com",
		"scea.com",
	}},
	{"xboxlive", "Xbox Live", "gaming", []string{
		"xboxlive.com", "xbox.com", "xboxab.com", "xboxservices.com", "gamepass.com",
	}},
	{"battlenet", "Battle.net", "gaming", []string{
		"battle.net", "blizzard.com", "blzstatic.cn", "battlenet.com.cn",
	}},
	{"riotgames", "Riot Games", "gaming", []string{
		"riotgames.com", "riotcdn.net", "leagueoflegends.com", "playvalorant.com", "pvp.net",
		"lolstatic.com", "lolesports.com",
	}},
	{"ea", "EA", "gaming", []string{
		"ea.com", "origin.com", "eaassets-a.akamaihd.net",
	}},
	// shopping
	{"amazon", "Amazon", "shopping", []string{
		"amazon.com", "amazon.de", "amazon.at", "amazon.co.uk", "amazon.fr", "amazon.it",
		"amazon.es", "amazon.nl", "amazon.pl", "amazon.se", "amazon.com.be", "amazon.ca",
		"amazon.com.au", "amazon.co.jp", "amazon.in", "amazon.com.tr", "amazon.com.mx",
		"amazon.com.br", "amazon.sg", "amazon.ae", "amazon.sa", "amazon.eg", "amazon.ie",
		"amazon.cn", "amzn.to", "amzn.eu", "amzn.com", "a.co", "ssl-images-amazon.com",
		"images-amazon.com", "media-amazon.com",
	}},
	{"ebay", "eBay", "shopping", []string{
		"ebay.com", "ebay.de", "ebay.at", "ebay.ch", "ebay.co.uk", "ebay.fr", "ebay.it", "ebay.es",
		"ebay.nl", "ebay.be", "ebay.pl", "ebay.ca", "ebay.com.au", "ebay.ie", "ebay.us",
		"ebayimg.com", "ebaystatic.com", "ebayrtm.com", "ebaydesc.com", "ebayinc.com",
	}},
	{"temu", "Temu", "shopping", []string{
		"temu.com", "kwcdn.com",
	}},
	{"aliexpress", "AliExpress", "shopping", []string{
		"aliexpress.com", "aliexpress.us", "aliexpress.ru", "aliexpress-media.com", "alicdn.com",
	}},
	{"shein", "SHEIN", "shopping", []string{
		"shein.com", "shein.co.uk", "ltwebstatic.com",
	}},
	// ai
	{"chatgpt", "ChatGPT", "ai", []string{
		"chatgpt.com", "openai.com", "oaistatic.com", "oaiusercontent.com", "sora.com",
	}},
	{"claude", "Claude", "ai", []string{
		"claude.ai", "claude.com", "anthropic.com", "claudeusercontent.com",
	}},
	{"gemini", "Google Gemini", "ai", []string{
		"gemini.google.com", "bard.google.com", "aistudio.google.com",
		"notebooklm.google.com",
	}},
	{"copilot", "Microsoft Copilot", "ai", []string{
		"copilot.microsoft.com", "copilot.cloud.microsoft", "sydney.bing.com",
	}},
	{"perplexity", "Perplexity", "ai", []string{
		"perplexity.ai", "pplx.ai",
	}},
	{"mistral", "Mistral AI", "ai", []string{
		"mistral.ai",
	}},
	{"deepseek", "DeepSeek", "ai", []string{
		"deepseek.com",
	}},
	// other
	{"tinder", "Tinder", "other", []string{
		"tinder.com", "gotinder.com", "tindersparks.com",
	}},
	{"9gag", "9GAG", "other", []string{
		"9gag.com", "9cache.com", "9gaggag.com",
	}},
}

// catalog is the sorted service catalog, built once.
var catalog = buildCatalog()

func buildCatalog() []Service {
	out := make([]Service, 0, len(serviceDefs))
	for _, d := range serviceDefs {
		s := Service{ID: d.id, Name: d.name, Group: d.group, Rules: make([]string, 0, len(d.domains))}
		for _, dom := range d.domains {
			s.Rules = append(s.Rules, "||"+dom+"^")
		}
		out = append(out, s)
	}
	slices.SortStableFunc(out, func(a, b Service) int {
		if ga, gb := slices.Index(serviceGroups, a.Group), slices.Index(serviceGroups, b.Group); ga != gb {
			return ga - gb
		}
		return strings.Compare(strings.ToLower(a.Name), strings.ToLower(b.Name))
	})
	return out
}

// Services returns the catalog, ordered by group then name (docs/design.md → Blocked services).
// Groups are ordered as in docs/api.md (social, messenger, video, music, gaming, shopping, ai,
// other). The result is a copy.
func Services() []Service {
	out := make([]Service, len(catalog))
	for i, s := range catalog {
		s.Rules = slices.Clone(s.Rules)
		out[i] = s
	}
	return out
}

// KnownService reports whether id is in the catalog.
func KnownService(id string) bool {
	_, ok := serviceByID[id]
	return ok
}

var serviceByID = func() map[string]int {
	m := make(map[string]int, len(catalog))
	for i, s := range catalog {
		m[s.ID] = i
	}
	return m
}()

// serviceRef is one catalog domain: the service (index into catalog) and its rule text.
type serviceRef struct {
	svc  int
	rule string
}

// serviceIndex maps every catalog domain to the services that block it.
type serviceIndex map[string][]serviceRef

func newServiceIndex() serviceIndex {
	idx := make(serviceIndex)
	for i, s := range catalog {
		for _, r := range s.Rules {
			dom := strings.TrimSuffix(strings.TrimPrefix(r, "||"), "^")
			idx[dom] = append(idx[dom], serviceRef{svc: i, rule: r})
		}
	}
	return idx
}

// check returns the most specific service rule among the blocked services ids that
// matches name (the name or one of its parent domains).
func (idx serviceIndex) check(name string, ids []string) (Result, bool) {
	if len(ids) == 0 || name == "" {
		return Result{}, false
	}
	for s, ok := name, true; ok; s, ok = parentDomain(s) {
		for _, ref := range idx[s] {
			id := catalog[ref.svc].ID
			if slices.Contains(ids, id) {
				return Result{Action: Block, Reason: ReasonService, Rule: ref.rule, Service: id}, true
			}
		}
	}
	return Result{}, false
}
