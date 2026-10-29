package main

// Evasion rules ported from the mitmproxy iboss_unblock_addon.
// Each rule maps a blocked domain suffix to an allowed SNI hostname,
// an optional pinned IP, and whether to relax upstream cert hostname check.

type EvasionRule struct {
	Suffix  string // domain suffix to match (e.g., "wordpress.com")
	SNI     string // upstream SNI to send instead
	IP      string // optional pinned IP (empty = use DNS)
	Relaxed bool   // skip upstream cert hostname check (YouTube/Google CDN)
}

var evasionRules = []EvasionRule{
	{"wordpress.com", "en.wordpress.com", "", false},
	{"gemini.google.com", "www.google.com", "", false},
	{"youtube.com", "www.google.com", "", true},
	{"ytimg.com", "www.google.com", "", true},
	{"googlevideo.com", "www.google.com", "", true},
	{"youtube-nocookie.com", "www.google.com", "", true},
	{"youtu.be", "www.google.com", "", true},
	// iBoss kills most reddit SNIs even to the clean IP, but alb.reddit.com
	// passes and Fastly serves the *.reddit.com wildcard cert. Host header
	// routes every reddit-family vhost on that edge.
	{"reddit.com", "alb.reddit.com", "151.101.1.140", false},
	{"redd.it", "alb.reddit.com", "151.101.1.140", false},
	{"redditmedia.com", "alb.reddit.com", "151.101.1.140", false},
	{"redditstatic.com", "alb.reddit.com", "151.101.1.140", false},
	// crates.io (rust registry) — on Fastly tolerant class, edge serves
	// alb.reddit.com cert, routes by Host header.
	{"crates.io", "alb.reddit.com", "", true},
}

func matchEvasion(host string) *EvasionRule {
	for i := range evasionRules {
		r := &evasionRules[i]
		if host == r.Suffix || (len(host) > len(r.Suffix) && host[len(host)-len(r.Suffix)-1] == '.' && host[len(host)-len(r.Suffix):] == r.Suffix) {
			return r
		}
	}
	return nil
}
