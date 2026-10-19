package report

import (
	"testing"

	reportv0 "github.com/KhaledSaeed18/urljail/gen/urljail/report/v0"
)

func TestPageBrand(t *testing.T) {
	for _, c := range []struct {
		name, text, domain string
		alts               []string
		want               string // brand ID, "" for none
	}{
		{name: "Outlook kit footer", text: "Sign In Please sign in to continue. User Account Password Keep me signed in Sign in © 2023 Microsoft", domain: "amazonaws.com", want: "microsoft"},
		{name: "copyright word", text: "Copyright © 2026 PayPal, Inc. All rights reserved.", domain: "evil.example", want: "paypal"},
		{name: "the brand's own page", text: "© 2026 Microsoft", domain: "microsoft.com", want: ""},
		{name: "a footer naming two brands, one owning the domain", text: "© 2026, Amazon Web Services, Inc. or its affiliates.", domain: "amazonaws-us-gov.com", want: ""},
		{name: "a site's own copyright", text: "© 2026 Rossman Partners. Built on WordPress.", domain: "rossmanpartners.com", want: ""},
		{name: "logo alt", text: "Verify Your Email", alts: []string{"Microsoft Logo"}, domain: "webstarterz.com", want: "microsoft"},
		{name: "sign in with Google buttons carry its logo", text: "Log in Email Password or Sign in with Google", alts: []string{"Google"}, domain: "someapp.example", want: ""},
		{name: "continue with", text: "Continue with Apple", alts: []string{"Apple ID"}, domain: "someapp.example", want: ""},
	} {
		b, _, ok := pageBrand(pageText{text: c.text, alts: c.alts}, c.domain)
		got := ""
		if ok {
			got = b.ID
		}
		if got != c.want {
			t.Errorf("%s: brand %q, want %q", c.name, got, c.want)
		}
	}
}

func TestFieldNameAndContactForms(t *testing.T) {
	for in, want := range map[string]string{"form_fields[message]": "message", "Email": "email", "items[]": "items[]", "a[b][c]": "c"} {
		if got := fieldName(in); got != want {
			t.Errorf("fieldName(%q) = %q, want %q", in, got, want)
		}
	}
	elementor := &reportv0.Form{Fields: []*reportv0.Field{{Type: "hidden", Name: "post_id"}, {Type: "text", Name: "form_fields[name]"},
		{Type: "email", Name: "form_fields[email]"}, {Type: "textarea", Name: "form_fields[message]"}}}
	if !commentForm(elementor) || asksForDetails([]*reportv0.Form{elementor}) {
		t.Error("an Elementor contact form must read as a contact form, not as asking for details")
	}
}
