package brands

import (
	"testing"

	"github.com/KhaledSaeed18/urljail/internal/visual"
)

func TestNamed(t *testing.T) {
	for text, want := range map[string]string{
		"PayPal: Log in to your account":                "paypal",
		"Sign in - Google Accounts":                     "google",
		"Amazon Web Services Sign-In":                   "amazon aws",
		"Wells Fargo – Sign On":                         "wellsfargo",
		"APPLE4D - Terbaik & Terbesar Number 1 di Asia": "", // "apple" alone isn't a brand word, and 4D joins it
		"Sign in | Snappy Kraken":                       "", // kraken is left out: an ordinary word
		"ログイン - 二軸押出機 J-WiSe ポータル":                      "",
		"Track your DHL parcel":                         "dhl",
		"paypal-login-secure":                           "paypal",
		"Ruby Affs":                                     "",
	} {
		var got string
		for i, b := range Named(text) {
			if i > 0 {
				got += " "
			}
			got += b.ID
		}
		if got != want {
			t.Errorf("Named(%q) = %q, want %q", text, got, want)
		}
	}
}

func TestOwnsAndList(t *testing.T) {
	seen := map[string]bool{}
	for _, b := range All {
		if seen[b.ID] || b.Name == "" || len(b.Words) == 0 || len(b.Domains) == 0 {
			t.Errorf("bad brand entry %+v", b)
		}
		seen[b.ID] = true
	}
	p, _ := ByID("paypal")
	if !p.Owns("paypal.com") || !p.Owns("PayPal.com") || p.Owns("paypal-secure.com") {
		t.Error("Owns")
	}
}

func TestRefsParse(t *testing.T) {
	for _, r := range Refs() {
		if _, ok := ByID(r.Brand); !ok {
			t.Errorf("ref for unknown brand %q", r.Brand)
		}
		if _, err := visual.Parse(r.Phash); err != nil {
			t.Errorf("ref %s: %v", r.Brand, err)
		}
	}
}

func TestDomainOf(t *testing.T) {
	for in, want := range map[string]string{
		"https://login.example.co.uk/x":               "example.co.uk",
		"blob:https://notaria11medellin.com/3f42-89#": "notaria11medellin.com",
		"BLOB:https://a.b.example.org/x":              "example.org",
		"about:blank":                                 "",
		"data:text/html,hi":                           "",
	} {
		if got := DomainOf(in); got != want {
			t.Errorf("DomainOf(%q) = %q, want %q", in, got, want)
		}
	}
}
