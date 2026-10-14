package report

import "strings"

// freeHosts are services where anyone can publish a page under the service's own domain, for
// free and in minutes, plus dynamic DNS. Kits live there because the domain is reputable and
// free: of the live feed pages in P7, every one with a password field or a details form on
// these hosts was phishing (journal P7, S4). Matched as host suffixes.
var freeHosts = []string{
	"replit.app", "repl.co", "vercel.app", "netlify.app", "pages.dev", "workers.dev", "r2.dev",
	"github.io", "gitlab.io", "gitbook.io", "webflow.io", "framer.app", "framer.website", "carrd.co",
	"4everland.app", "glitch.me", "firebaseapp.com", "web.app", "onrender.com", "herokuapp.com",
	"fly.dev", "railway.app", "surge.sh", "amplifyapp.com", "azurewebsites.net", "web.core.windows.net",
	"blob.core.windows.net", "storage.googleapis.com", "s3.amazonaws.com", "ngrok-free.app", "ngrok.io",
	"blogspot.com", "godaddysites.com", "wixsite.com", "weebly.com", "square.site", "squarespace.com",
	"wordpress.com", "notion.site", "my.canva.site", "cpanel.site", "ipfs.io", "dweb.link",
	"duckdns.org", "ddnss.de", "dyndns.org", "ddns.net", "no-ip.org", "no-ip.biz", "hopto.org", "zapto.org",
}

// freeHost returns the free hosting service a host is published under, or "".
func freeHost(host string) string {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	for _, s := range freeHosts {
		if host == s || strings.HasSuffix(host, "."+s) {
			return s
		}
	}
	return ""
}
