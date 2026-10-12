package feeds

import (
	"slices"
	"strings"

	"golang.org/x/net/publicsuffix"
)

// Scoring certificate names for phishing (P6 own discovery). Deliberately simple and
// explainable: every point has a reason recorded with the candidate, so the hit rate can be
// measured per rule against what the detonations show.

// brands are names phishing kits impersonate most (feeds and reports, 2025-2026).
var brands = []string{
	"paypal", "apple", "icloud", "microsoft", "office365", "outlook", "onedrive", "sharepoint",
	"amazon", "netflix", "facebook", "instagram", "whatsapp", "google", "gmail", "dropbox",
	"docusign", "adobe", "linkedin", "coinbase", "binance", "metamask", "trustwallet", "ledger",
	"kraken", "blockchain", "chase", "wellsfargo", "bankofamerica", "citibank", "hsbc", "barclays",
	"santander", "lloyds", "natwest", "revolut", "wise", "usps", "fedex", "dhl", "ups", "auspost",
	"royalmail", "canadapost", "evri", "ebay", "walmart", "steam", "roblox", "spotify", "irs",
	"hmrc", "ato", "mygov", "netbank", "stripe", "shopify", "telegram", "discord",
	"td", "tdbank", "rbc", "scotiabank", "interac", "commbank", "westpac", "anz", "nab",
	"ing", "bbva", "pnc", "capitalone", "amex", "americanexpress", "venmo", "cashapp", "zelle",
	"rakuten", "docomo", "aeon", "smbc", "mufg", "jcb", "mercari", "yamato", "sagawa", "japanpost",
	"lineme", "kakao", "naver", "orange", "laposte", "ameli", "correos", "posteitaliane",
}

// shortBrands match only as a whole token: as substrings they'd hit ordinary words.
var shortBrands = map[string]bool{"ups": true, "dhl": true, "irs": true, "ato": true, "wise": true, "evri": true,
	"ebay": true, "chase": true, "steam": true, "apple": true, "ledger": true, "rbc": true, "anz": true, "nab": true,
	"ing": true, "td": true, "pnc": true, "amex": true, "aeon": true, "smbc": true, "jcb": true, "orange": true, "ameli": true}

var actions = []string{
	"login", "signin", "logon", "verify", "verification", "secure", "security", "account", "update",
	"unlock", "support", "wallet", "recover", "recovery", "auth", "confirm", "billing", "payment",
	"invoice", "delivery", "parcel", "track", "tracking", "refund", "suspend", "suspended", "alert",
	"validate", "reactivate", "claim", "reward", "bonus", "airdrop", "service", "help", "online",
}

var cheapTLDs = map[string]bool{
	"top": true, "xyz": true, "icu": true, "cyou": true, "sbs": true, "shop": true, "click": true,
	"online": true, "site": true, "live": true, "info": true, "buzz": true, "rest": true, "cfd": true,
	"lol": true, "bond": true, "vip": true, "support": true, "help": true, "store": true, "work": true,
	"cc": true, "co": true, "app": true, "dev": true, "pro": true, "life": true, "today": true, "win": true,
}

// legit are registrable domains that are the brands themselves or hosting platforms whose
// customer subdomains don't get their own certificates.
var legit = map[string]bool{
	"paypal.com": true, "apple.com": true, "icloud.com": true, "microsoft.com": true, "office.com": true,
	"office365.com": true, "outlook.com": true, "live.com": true, "sharepoint.com": true, "onedrive.com": true,
	"amazon.com": true, "amazonaws.com": true, "netflix.com": true, "facebook.com": true, "instagram.com": true,
	"whatsapp.com": true, "google.com": true, "gmail.com": true, "dropbox.com": true, "docusign.com": true,
	"docusign.net": true, "adobe.com": true, "linkedin.com": true, "coinbase.com": true, "binance.com": true,
	"metamask.io": true, "ledger.com": true, "kraken.com": true, "blockchain.com": true, "chase.com": true,
	"wellsfargo.com": true, "bankofamerica.com": true, "citi.com": true, "hsbc.com": true, "barclays.co.uk": true,
	"revolut.com": true, "wise.com": true, "usps.com": true, "fedex.com": true, "dhl.com": true, "ups.com": true,
	"auspost.com.au": true, "royalmail.com": true, "ebay.com": true, "walmart.com": true, "steampowered.com": true,
	"roblox.com": true, "spotify.com": true, "irs.gov": true, "stripe.com": true, "shopify.com": true,
	"myshopify.com": true, "telegram.org": true, "discord.com": true, "azurewebsites.net": true,
	"cloudfront.net": true, "microsoft-int.com": true, "msftauth.net": true, "azure.com": true, "appleid.apple.com": true, "herokuapp.com": true, "vercel.app": true, "netlify.app": true, "pages.dev": true,
	"workers.dev": true, "github.io": true, "web.app": true, "firebaseapp.com": true,
}

// homoglyphs are the substitutions lookalike domains use most.
var homoglyphs = strings.NewReplacer("0", "o", "1", "l", "3", "e", "4", "a", "5", "s", "rn", "m", "vv", "w")

// Score rates a certificate DNS name. Candidates have score ≥ CandidateScore; reasons say why.
func Score(name string) (score int, reasons []string) {
	name = strings.TrimPrefix(strings.ToLower(name), "*.")
	reg, err := publicsuffix.EffectiveTLDPlusOne(name)
	if err != nil || legit[reg] {
		return 0, nil
	}
	suffix, _ := publicsuffix.PublicSuffix(name)
	rest := strings.TrimSuffix(name, "."+suffix) // everything the registrant chose
	regLabel := strings.TrimSuffix(reg, "."+suffix)
	split := func(s string) []string {
		return strings.FieldsFunc(s, func(r rune) bool { return r == '.' || r == '-' || r >= '0' && r <= '9' })
	}
	tokens := split(rest)
	plain := strings.Join(tokens, "")

	// A brand in the registered name itself (paypal-verify.com) counts more than one in a
	// subdomain of an unrelated name (paypal.verify.example.com), which hosting setups produce.
	brand, inReg := "", false
	for _, b := range brands {
		regTokens := split(regLabel)
		switch {
		case shortBrands[b] && (slices.Contains(regTokens, b) || gluedToAction(regTokens, b)),
			!shortBrands[b] && strings.Contains(strings.Join(regTokens, ""), b):
			brand, inReg = b, true
		case !shortBrands[b] && strings.Contains(homoglyphs.Replace(strings.ReplaceAll(regLabel, "-", "")), b):
			brand, inReg = b, true
			score++
			reasons = append(reasons, "lookalike")
		case shortBrands[b] && slices.Contains(tokens, b), !shortBrands[b] && strings.Contains(plain, b):
			brand = b
		}
		if brand != "" {
			break
		}
	}
	if brand != "" {
		if inReg {
			score += 3
			reasons = append(reasons, "brand:"+brand)
		} else {
			score += 2
			reasons = append(reasons, "brand-in-subdomain:"+brand)
		}
	}
	nAct := 0
	for _, a := range actions {
		if strings.Contains(plain, a) && nAct < 3 {
			nAct++
			reasons = append(reasons, "word:"+a)
		}
	}
	score += nAct
	if cheapTLDs[suffix] {
		score++
		reasons = append(reasons, "tld:"+suffix)
	}
	if strings.Count(regLabel, "-") >= 2 {
		score++
		reasons = append(reasons, "hyphens")
	}
	if generated(rest) {
		score -= 2
		reasons = append(reasons, "generated")
	}
	// Without a brand, words alone are mostly ordinary business names; only a pile of them on
	// a cheap TLD (secure-account-verify.top) counts.
	if brand == "" && !(nAct >= 3 && cheapTLDs[suffix]) {
		return min(score, CandidateScore-1), reasons
	}
	return score, reasons
}

// CandidateScore is the minimum score worth a detonation: a brand plus at least one more sign.
const CandidateScore = 4

// generated reports labels that look machine-made (long, digit-heavy): service hostnames,
// not something shown to a victim.
func generated(rest string) bool {
	for _, l := range strings.Split(rest, ".") {
		digits := 0
		for _, c := range l {
			if c >= '0' && c <= '9' {
				digits++
			}
		}
		if len(l) > 30 || len(l) >= 12 && digits*3 >= len(l) {
			return true
		}
	}
	return false
}

// gluedToAction reports a token that is a short brand followed by an action word, as
// lookalikes write them ("tdaccounts", "dhldelivery", "upstracking").
func gluedToAction(tokens []string, brand string) bool {
	for _, t := range tokens {
		if rest, ok := strings.CutPrefix(t, brand); ok && rest != "" {
			for _, a := range actions {
				if strings.HasPrefix(rest, a) {
					return true
				}
			}
		}
	}
	return false
}
