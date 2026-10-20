package report

import (
	"regexp"
	"strings"
)

// A fake software update: a page that says the visitor's software is out of date, or tells them
// to update or download a reader, client or browser, and backs it with an install step or a
// device requirement. What malware lures look like when they come through a phishing feed
// (found in P7, S22: a "PDF Viewer" kit telling the visitor to update Adobe PDF Reader, with
// "Windows computer required" for any other system, on six hacked sites over sets 5, 6 and 8;
// a "Zoom Client Update" kit redirecting to a download). Its installer instructions sat in a
// template, so only the visible claim and requirement are read.
var (
	updateClaim = regexp.MustCompile(`(?i)\b(is|are) (out of date|outdated)\b|\bupdate required\b|\bneeds? (to be )?updat(ed|ing)\b|` +
		`\b(update|download|install) (or download )?(the )?(latest (version of )?)?(adobe|acrobat|pdf reader|reader|zoom|teams|chrome|browser|flash|media player|codec|font)\b|` +
		`\bmissing (font|plugin|codec)\b`)
	updateStep = regexp.MustCompile(`(?i)double\W?click\b.{0,60}\b(installer|setup|\.exe|\.msi|\.zip|file)\b|\b(installer|setup) (file|package)\b|` +
		`\bredirected to (the )?microsoft store\b|\bdownload(ing)? (will )?start(s|ed)? automatically\b|` +
		`\b(designed for|requires?|only (works|runs) on) (a )?windows (desktop |laptop )?(computers?|pcs?)\b|\bwindows (desktop |laptop )?(computer|pc) required\b`)
)

// fakeUpdate returns the claim and the step that make the page a fake software update.
func fakeUpdate(text string) (claim, step string, ok bool) {
	c, s := updateClaim.FindString(text), updateStep.FindString(text)
	return strings.ToLower(c), strings.ToLower(s), c != "" && s != ""
}

// A wallet's "send" screen as a web page: a short page with send or transfer wording, a coin
// ticker and at least two of a send form's labels (amount, recipient, address, max). Wallets
// show this screen in their app or extension, not on a public page; a page that does wants the
// visitor to send coins to the address it fills in (found in P7, S22: "Transfer Trust Wallet"
// and "Send - Trust Wallet" pages on vercel and netlify, labelled payment in sets 3 and 8).
var (
	sendWords   = regexp.MustCompile(`(?i)\b(send|transfer|withdraw)\b`)
	coinTicker  = regexp.MustCompile(`\b(USDT|USDC|BTC|ETH|BNB|TRX|SOL)\b`)
	sendLabels  = regexp.MustCompile(`(?i)\b(amount|address or domain|recipient|to address|max)\b`)
	maxSendPage = 150 // words
)

// cryptoSend reports whether the page is a coin send screen, with the ticker it names.
func cryptoSend(p pageText) (string, bool) {
	if p.words > maxSendPage || !sendWords.MatchString(p.text) {
		return "", false
	}
	coin := coinTicker.FindString(p.text)
	labels := map[string]bool{}
	for _, l := range sendLabels.FindAllString(p.text, -1) {
		labels[strings.ToLower(l)] = true
	}
	return coin, coin != "" && len(labels) >= 2
}
