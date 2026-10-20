package report

import (
	"strings"
	"testing"
)

func TestFakeUpdate(t *testing.T) {
	for _, c := range []struct {
		name, text string
		want       bool
	}{
		{"the PDF Viewer kit", "PDF Viewer 💻 Windows Computer Required This content is designed for Windows desktop computers only . " +
			"These secured PDF files were created using the latest version of Adobe. Please update or download Adobe PDF Reader to view them.", true},
		{"the Zoom kit", "Zoom Client Update Please wait... Your Zoom Client is Out of Date Please wait while you're redirected to Microsoft Store...", true},
		{"install steps", "Your browser is out of date. Double‑click the setup file in your Downloads to finish.", true},
		{"a software download site", "Download the latest version of Adobe Reader for free. Fast and safe downloads.", false},
		{"a game that needs Windows", "This game requires a Windows PC with 8 GB of RAM.", false},
		{"an article about updates", "Microsoft Teams needs updating every month; here is how IT teams roll it out.", false},
	} {
		if _, _, got := fakeUpdate(c.text); got != c.want {
			t.Errorf("%s: fakeUpdate = %v, want %v", c.name, got, c.want)
		}
	}
}

func TestCryptoSend(t *testing.T) {
	for _, c := range []struct {
		name, text string
		want       bool
	}{
		{"Trust Wallet send kit", "Transfer Trust Wallet Send USDT Address or Domain Name Paste Amount USDT Max ≈ $1.00 Next", true},
		{"amount keypad kit", "Transfer Trust Wallet ‹ Amount To: ≈ $0.00 0.00000000 USDT $0.00 Max 1 2 3 4 5 6 7 8 9 . 0 ⌫ Review", true},
		{"an exchange's price ticker", "BTC $67,000 ETH $3,100 Send money abroad with low fees", false},
		{"no ticker", "Send money Amount Recipient Max", false},
	} {
		words := len(strings.Fields(c.text))
		if _, got := cryptoSend(pageText{text: c.text, words: words}); got != c.want {
			t.Errorf("%s: cryptoSend = %v, want %v", c.name, got, c.want)
		}
	}
}
