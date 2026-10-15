package report

import (
	"fmt"
	"regexp"
	"strings"

	reportv0 "github.com/KhaledSaeed18/urljail/gen/urljail/report/v0"
	"github.com/KhaledSaeed18/urljail/internal/brands"
)

// Lures are a brand's pages that ask for nothing yet: a wallet "setup guide" that sends the
// visitor to a fake app, a fake "your account was hacked" alert, a prize draw. The form and
// password rules never see them, and naming the brand alone doesn't tell them from tutorial
// clones of Netflix's home page (journal P7: 77 labelled lures, 7 flagged). What tells them
// apart, on the labelled pages, is how they name the brand and what they say about it.

// alarmWording is a page telling the visitor something has gone wrong with their account or
// device: what fake security alerts open with.
var alarmWording = regexp.MustCompile(`(?i)\b(ha(s|ve) been hacked|been compromised|virus(es)? (ha(s|ve) been |were |was )?detected|(detected|found) (a |\d+ )?virus|suspended your account|` +
	`account (has been |was |is |will be )?(temporarily |permanently )?(suspended|locked|disabled|deactivated|restricted|blocked)|has (temporarily |permanently )?(suspended|disabled|locked)|` +
	`community standards|security alert|(unusual|suspicious) (sign.in |login )?activity|` +
	`cuenta (ha sido |fue |est[áa] )?(suspendida|bloqueada|desactivada)|conta (foi |est[áa] )?(suspensa|bloqueada|desativada)|compte (a [ée]t[ée] |est )?(suspendu|bloqu[ée]|d[ée]sactiv[ée])|` +
	`konto (wurde |ist )?(gesperrt|deaktiviert)|akun (anda )?(telah |akan )?(diblokir|dinonaktifkan|ditangguhkan)|account ([èe] stato )?(sospeso|bloccato))\b`)

// offerWording is a prize, a reward or an offer: what prize-draw and loan lures say.
var offerWording = regexp.MustCompile(`(?i)\b(winners?|congratulations|you('ve| have)? won([ !.,:]|$)|prizes?|claim (now|your|it)|free robux|giveaway|rewards? for you|limit offer|pre-?approved|exclusive offer|` +
	`hadiah|pemenang|klaim|premios?|ganador(es)?|oferta exclusiva|sorteio|ganhador(es)?|gagnant|gewinner|gewinnspiel)\b`)

// officialClaim is a title calling itself official or carrying a trademark sign.
var officialClaim = regexp.MustCompile(`(?i)\bofficial\b|®|™`)

// lureIndicators adds the lure rules. segments are the title (without the host) and the headings;
// pt the page's visible text. Never on a brand's own domain.
func lureIndicators(domain string, segments []string, pt pageText, havePage bool) []*reportv0.Indicator {
	text := strings.Join(segments, " \n ")
	if _, owned := brands.Owner(domain); owned {
		return nil
	}
	var out []*reportv0.Indicator

	// A brand's own domain written in the title or headings, off it: "Official Site® |
	// Ledger.com/Start®" on typedream.app. A page that is the brand is on its domain; one that
	// writes it out is pointing at it (found in P7: Ledger and Trezor setup-guide pages on
	// typedream, gitbook and pages.dev, 12 of the labelled lures).
	if b, d, ok := brands.DomainWritten(text); ok && !b.Owns(domain) {
		out = append(out, &reportv0.Indicator{
			Id: "brand-domain-in-title", Severity: "medium", Brand: b.ID, Source: guestDOM,
			Detail: fmt.Sprintf("The title or headings write %s, %s's own domain, on %s", d, b.Name, domain),
		})
	}

	// A brand written with accents or look-alike letters: a brand's own pages spell its name
	// plainly; kits disguise it from filters ("Trézór Suite (Official)", "KÚCÔIN LÔGIN").
	// Each of the title and headings on its own: a kit may spell the brand plainly in one and
	// disguise it in another ("Trézór Suite (Official)" over a heading "Trezor Suite: ...").
	for _, seg := range segments {
		if ds := brands.Disguised(seg); len(ds) > 0 && !ds[0].Owns(domain) {
			out = append(out, &reportv0.Indicator{
				Id: "brand-name-disguised", Severity: "medium", Brand: ds[0].ID, Source: guestDOM,
				Detail: fmt.Sprintf("The title or headings spell %s with accents or look-alike letters, on %s", ds[0].Name, domain),
			})
			break
		}
	}

	// A brand named in the title with a claim to be its official site or a trademark sign, off
	// the brand's domains: the brand's own site doesn't need to say so ("Ledger® Live App |
	// Official Site®" on typedream.app, "Official Trezor™ Suite App" on b12sites.com).
	if tb := brands.Named(segments[0]); len(tb) > 0 && !tb[0].Owns(domain) {
		if m := officialClaim.FindString(segments[0]); m != "" {
			out = append(out, &reportv0.Indicator{
				Id: "brand-official-claim", Severity: "medium", Brand: tb[0].ID, Source: guestDOM,
				Detail: fmt.Sprintf("The title names %s and claims to be official (%q), on %s", tb[0].Name, strings.ToLower(m), domain),
			})
		}
	}

	named := brands.Named(text)
	if len(named) == 0 || !havePage {
		return out
	}
	b := named[0]
	for _, n := range named {
		if n.Owns(domain) {
			return out
		}
	}
	body := text + " \n " + pt.text

	// A brand named, and the page says the visitor's account or device is in trouble: a fake
	// security alert (found in P7: one "your Android has been hacked" Gmail kit on 12 sites).
	if m := alarmWording.FindString(body); m != "" {
		out = append(out, &reportv0.Indicator{
			Id: "brand-alert-off-domain", Severity: "medium", Brand: b.ID, Source: guestDOM,
			Detail: fmt.Sprintf("The page names %s in its title or headings and warns of trouble (%q), on %s", b.Name, strings.ToLower(m), domain),
		})
	}
	// A brand named, and a prize, reward or offer (found in P7: Shopee prize draws on blogspot,
	// "Free Robux", an Apple Card credit-limit offer).
	if m := offerWording.FindString(body); m != "" {
		out = append(out, &reportv0.Indicator{
			Id: "brand-offer-off-domain", Severity: "medium", Brand: b.ID, Source: guestDOM,
			Detail: fmt.Sprintf("The page names %s in its title or headings and offers a prize or reward (%q), on %s", b.Name, strings.ToLower(m), domain),
		})
	}
	return out
}
