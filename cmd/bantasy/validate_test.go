package main

import (
	"strings"
	"testing"
	"time"
)

func TestParseTTL(t *testing.T) {
	for text, want := range map[string]time.Duration{
		"30m": 30 * time.Minute, "24h": 24 * time.Hour, "7d": 7 * 24 * time.Hour, "never": 0,
	} {
		got, err := parseTTL(text)
		if err != nil || got != want {
			t.Errorf("parseTTL(%q) = %v, %v; want %v", text, got, err, want)
		}
	}

	for _, text := range []string{"", "0h", "24", "1w", "-1d", "1.5h", "36501d", "99999999999999999999d"} {
		if _, err := parseTTL(text); err == nil {
			t.Errorf("parseTTL(%q) gave no error", text)
		}
	}
}

func TestNormaliseIP(t *testing.T) {
	for _, c := range [][2]string{
		{" 45.33.32.7 ", "45.33.32.7"},
		{"45.33.32.7/32", "45.33.32.7"},
		{"81.2.69.77/24", "81.2.69.0/24"},
		{"2001:4860:4860::8888", "2001:4860:4860::8888"},
		{"2a00:1450:4000::1/48", "2a00:1450:4000::/48"},
		{"52.64.0.0/16", "52.64.0.0/16"},
	} {
		got, err := normaliseIP(c[0])
		if err != nil || got != c[1] {
			t.Errorf("normaliseIP(%q) = %q, %v; want %q", c[0], got, err, c[1])
		}
	}

	refused := []string{
		// Not public.
		"10.1.2.3", "192.168.0.0/24", "100.64.0.0/16", "127.0.0.1", "169.254.1.1", "224.0.0.1",
		"240.0.0.1", "0.0.0.0", "::1", "198.51.100.1", "fd00::1", "fe80::1", "::ffff:45.33.32.7",
		"2001:db8::1", "ff02::1",
		// Overlaps a special range.
		"192.0.0.0/16",
		// Too wide.
		"52.0.0.0/8", "52.64.0.0/15", "2a00::/16",
		// Junk.
		"", "not-an-ip", "45.33.32.300", "45.33.32.7/33", "fe80::1%eth0",
	}
	for _, text := range refused {
		if got, err := normaliseIP(text); err == nil {
			t.Errorf("normaliseIP(%q) = %q, want an error", text, got)
		}
	}
}

func TestNormaliseDomain(t *testing.T) {
	if got, err := normaliseDomain(" Mail.X.com. "); err != nil || got != "mail.x.com" {
		t.Errorf("got %q, %v", got, err)
	}

	for _, text := range []string{"", "com", "pat@x.com", "x..com", "-x.com", "x_y.com", "x.com/path"} {
		if _, err := normaliseDomain(text); err == nil {
			t.Errorf("normaliseDomain(%q) gave no error", text)
		}
	}
}

func TestNormaliseFragment(t *testing.T) {
	if got, err := normaliseFragment("  PhantomJsCloud.com "); err != nil || got != "PhantomJsCloud.com" {
		t.Errorf("got %q, %v", got, err)
	}

	for _, text := range []string{"", "   ", "M", " 5.0 ", "bot\nx", "bot\x00", strings.Repeat("x", 201)} {
		if _, err := normaliseFragment(text); err == nil {
			t.Errorf("normaliseFragment(%q) gave no error", text)
		}
	}
}

func TestCheckPath(t *testing.T) {
	if got, err := checkPath(`^/wp-login\.php`); err != nil || got != `^/wp-login\.php` {
		t.Errorf("got %q, %v", got, err)
	}

	for _, text := range []string{"", "(unclosed"} {
		if _, err := checkPath(text); err == nil {
			t.Errorf("checkPath(%q) gave no error", text)
		}
	}
}

func TestCheckAction(t *testing.T) {
	for _, a := range []string{"block", "allow", "ban-ip", "signal", "smartypants:block-signup"} {
		if err := checkAction(a); err != nil {
			t.Errorf("checkAction(%q): %v", a, err)
		}
	}

	for _, a := range []string{"ban", ":x", "x:", "Block"} {
		if err := checkAction(a); err == nil {
			t.Errorf("checkAction(%q) gave no error", a)
		}
	}
}

func TestRuleID(t *testing.T) {
	for _, c := range [][4]string{
		{"smartypants", "email-domain", "x.com", "smartypants:email-domain:x.com"},
		{"ops", "user-agent", "PhantomJsCloud.com", "ops:user-agent:phantomjscloud.com"},
		{"ops", "referrer", "Spam.Example", "ops:referrer:spam.example"},
		{"ops", "path", "^/Admin", "ops:path:^/Admin"},
		{"ops", "ip", "81.2.69.0/24", "ops:ip:81.2.69.0/24"},
	} {
		if got := ruleID(c[0], c[1], c[2]); got != c[3] {
			t.Errorf("ruleID(%q, %q, %q) = %q, want %q", c[0], c[1], c[2], got, c[3])
		}
	}
}
