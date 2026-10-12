package report

import "strings"

// browserBackground lists endpoints Chrome contacts on its own (component updater, sign-in,
// push messaging, variations), as seen in P3's host-side capture despite the image's policies
// and --disable-background-networking. It only labels host-side traffic that no guest request
// explains: a page that loads one of these hosts itself is still labeled "page".
var browserBackground = []string{
	"gvt1.com",                   // redirector.gvt1.com, edgedl.me.gvt1.com, r*---sn-*.gvt1.com: component downloads
	"update.googleapis.com",      // component updater
	"clients1.google.com",        //
	"clients2.google.com",        //
	"accounts.google.com",        // sign-in / account state
	"www.google.com",             // startup and search-engine probes
	"android.clients.google.com", // push messaging (GCM) registration
	"mtalk.google.com",           // push messaging (GCM) connection
	"optimizationguide-pa.googleapis.com",
	"content-autofill.googleapis.com",
}

func isBackground(host string) bool {
	host = strings.TrimSuffix(strings.ToLower(host), ".")
	for _, b := range browserBackground {
		if host == b || strings.HasSuffix(host, "."+b) {
			return true
		}
	}
	return false
}
