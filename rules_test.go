package bantasy

import (
	"net/netip"
	"strings"
	"testing"
	"time"
)

var t0 = time.Date(2026, 11, 15, 3, 0, 0, 0, time.UTC)

func mustCompile(t *testing.T, jsonl string, now time.Time) *compiled {
	t.Helper()

	res := parseRules([]byte(jsonl))
	if len(res.warnings) > 0 {
		t.Fatalf("unexpected warnings: %v", res.warnings)
	}

	return compile(res.rules, now)
}

// matchID returns the id of the rule that decides the request, or "".
func matchID(c *compiled, ip, uri, ua, ref string) string {
	var a netip.Addr
	if ip != "" {
		a = netip.MustParseAddr(ip)
	}

	r := c.match(newRequest(a, uri, ua, ref))
	if r == nil {
		return ""
	}

	return r.ID
}

func TestMatchKinds(t *testing.T) {
	c := mustCompile(t, `{"id":"ip","kind":"ip","match":"203.0.113.0/24"}
{"id":"php","kind":"path","match":"(?i)\\.php($|\\?)"}
{"id":"ua","kind":"user-agent","match":"BadBot"}
{"id":"ref","kind":"referrer","match":"spam.example"}
`, t0)

	tests := []struct {
		name, ip, uri, ua, ref, want string
	}{
		{"ip match", "203.0.113.9", "/", "", "", "ip"},
		{"ip miss", "203.0.114.9", "/", "", "", ""},
		{"path match", "192.0.2.1", "/wp-login.PHP", "", "", "php"},
		{"path match with query", "192.0.2.1", "/x.php?a=1", "", "", "php"},
		{"path query is part of URI", "192.0.2.1", "/search?q=.php", "", "", "php"},
		{"path miss", "192.0.2.1", "/x.phpx", "", "", ""},
		{"ua match ignores case", "192.0.2.1", "/", "Mozilla badbot/1.0", "", "ua"},
		{"ua miss", "192.0.2.1", "/", "Mozilla/5.0", "", ""},
		{"referrer match ignores case", "192.0.2.1", "/", "", "https://SPAM.example/x", "ref"},
		{"referrer miss", "192.0.2.1", "/", "", "https://ok.example/", ""},
		{"no client IP still matches path", "", "/a.php", "", "", "php"},
		{"ip wins over path", "203.0.113.9", "/a.php", "BadBot", "", "ip"},
		{"path wins over user-agent", "192.0.2.1", "/a.php", "BadBot", "spam.example", "php"},
		{"user-agent wins over referrer", "192.0.2.1", "/", "BadBot", "spam.example", "ua"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := matchID(c, tt.ip, tt.uri, tt.ua, tt.ref); got != tt.want {
				t.Errorf("got %q, want %q", got, tt.want)
			}
		})
	}
}

func TestAllowBeatsBlock(t *testing.T) {
	c := mustCompile(t, `{"id":"block-net","kind":"ip","match":"198.51.0.0/16"}
{"id":"php","kind":"path","match":"\\.php"}
{"id":"office","kind":"ip","match":"198.51.100.0/24","action":"allow"}
{"id":"monitor","kind":"user-agent","match":"UptimeRobot","action":"allow"}
`, t0)

	tests := []struct {
		name, ip, uri, ua, want string
	}{
		{"allow ip beats block ip", "198.51.100.5", "/", "", "office"},
		{"allow ip beats block path", "198.51.100.5", "/a.php", "", "office"},
		{"allow ua beats block ip", "198.51.7.7", "/", "Mozilla UptimeRobot/2.0", "monitor"},
		{"allow ua beats block path", "192.0.2.1", "/a.php", "uptimerobot", "monitor"},
		{"block outside the allow", "198.51.7.7", "/", "", "block-net"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := matchID(c, tt.ip, tt.uri, tt.ua, ""); got != tt.want {
				t.Errorf("got %q, want %q", got, tt.want)
			}
		})
	}
}

func TestParseRule(t *testing.T) {
	tests := []struct {
		name    string
		line    string
		want    string // "load", "ignore <key>" or "warn <substring>"
		wantAct string // action of a loaded rule
	}{
		{"unknown field", `{"kind":"ip","match":"192.0.2.1","futureField":{"x":1}}`, "load", "block"},
		{"ban-ip on ip is block", `{"kind":"ip","match":"192.0.2.1","action":"ban-ip"}`, "load", "block"},
		{"ban-ip on path", `{"kind":"path","match":"^/admin","action":"ban-ip","banSeconds":60}`, "load", "ban-ip"},
		{"allow", `{"kind":"user-agent","match":"UptimeRobot","action":"allow"}`, "load", "allow"},
		{"foreign kind", `{"kind":"email-domain","match":"spam.example"}`, "ignore kind email-domain", ""},
		{"signal", `{"kind":"ip","match":"192.0.2.1","action":"signal"}`, "ignore action signal", ""},
		{"third-party action", `{"kind":"ip","match":"192.0.2.1","action":"smartypants:block-signup"}`, "ignore action smartypants:block-signup", ""},
		{"unknown action", `{"kind":"ip","match":"192.0.2.1","action":"quarantine"}`, "ignore action quarantine", ""},
		{"bad CIDR", `{"kind":"ip","match":"192.0.2.0/33"}`, "warn bad CIDR", ""},
		{"bad address", `{"kind":"ip","match":"nope"}`, "warn bad IP address", ""},
		{"bad regexp", `{"kind":"path","match":"(unclosed"}`, "warn bad regexp", ""},
		{"bad JSON", `not json`, "warn bad JSON", ""},
		{"bad expires", `{"kind":"ip","match":"192.0.2.1","expires":"tomorrow"}`, "warn bad JSON", ""},
		{"empty match", `{"kind":"path","match":""}`, "warn empty match", ""},
		{"no kind", `{"match":"192.0.2.4"}`, "warn no kind", ""},
		{"negative banSeconds", `{"kind":"path","match":"x","action":"ban-ip","banSeconds":-1}`, "warn banSeconds", ""},
		{"huge banSeconds", `{"kind":"path","match":"x","action":"ban-ip","banSeconds":99999999999}`, "warn banSeconds", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			res := parseRules([]byte(tt.line + "\n"))

			got := "load"

			switch {
			case len(res.warnings) == 1:
				got = "warn " + res.warnings[0]
			case len(res.ignored) == 1:
				for k := range res.ignored {
					got = "ignore " + k
				}
			case len(res.rules) != 1:
				t.Fatalf("no outcome: %+v", res)
			}

			if !strings.HasPrefix(tt.want, "warn ") && got != tt.want ||
				strings.HasPrefix(tt.want, "warn ") && !strings.Contains(got, strings.TrimPrefix(tt.want, "warn ")) {
				t.Errorf("got %q, want %q", got, tt.want)
			}

			if tt.wantAct != "" && len(res.rules) == 1 && res.rules[0].Action != tt.wantAct {
				t.Errorf("action = %q, want %q", res.rules[0].Action, tt.wantAct)
			}
		})
	}
}

func TestParseRulesLines(t *testing.T) {
	data := `{"id":"a","kind":"ip","match":"192.0.2.1"}

not json
{"id":"b","kind":"ip","match":"192.0.2.2"}
{"id":"c","kind":"ip","ma`

	res := parseRules([]byte(data))

	if len(res.rules) != 2 || res.rules[0].ID != "a" || res.rules[1].ID != "b" {
		t.Errorf("rules = %+v, want a and b", res.rules)
	}

	// The blank line counts; the partial last line gives no warning.
	if len(res.warnings) != 1 || !strings.HasPrefix(res.warnings[0], "line 3: bad JSON") {
		t.Errorf("warnings = %q, want one for line 3", res.warnings)
	}

	// A complete last line with no trailing newline loads.
	res = parseRules([]byte(`{"id":"a","kind":"ip","match":"192.0.2.1"}` + "\n" + `{"id":"z","kind":"ip","match":"192.0.2.9"}`))
	if len(res.rules) != 2 || res.rules[1].ID != "z" || len(res.warnings) != 0 {
		t.Errorf("unterminated complete line: rules %+v, warnings %q", res.rules, res.warnings)
	}
}

func TestSignalsAndForeignKindsNeverMatch(t *testing.T) {
	c := mustCompile(t, `{"id":"s","kind":"ip","match":"0.0.0.0/0","action":"signal"}
{"id":"f","kind":"email-domain","match":"spam.example"}
`, t0)

	if got := matchID(c, "192.0.2.1", "/spam.example", "spam.example", "spam.example"); got != "" {
		t.Errorf("got %q, want no match", got)
	}
}

func TestExpiry(t *testing.T) {
	c := mustCompile(t, `{"id":"past","kind":"ip","match":"192.0.2.1","expires":"2026-11-15T02:59:59Z"}
{"id":"future","kind":"ip","match":"192.0.2.2","expires":"2026-11-15T04:00:00Z"}
{"id":"later","kind":"ip","match":"192.0.2.3","expires":"2026-11-16T00:00:00Z"}
{"id":"null","kind":"ip","match":"192.0.2.4","expires":null}
`, t0)

	if got := matchID(c, "192.0.2.1", "/", "", ""); got != "" {
		t.Errorf("expired rule matched")
	}

	for _, ip := range []string{"192.0.2.2", "192.0.2.3", "192.0.2.4"} {
		if matchID(c, ip, "/", "", "") == "" {
			t.Errorf("live rule for %s did not match", ip)
		}
	}

	if want := time.Date(2026, 11, 15, 4, 0, 0, 0, time.UTC); !c.nextExpiry.Equal(want) {
		t.Errorf("nextExpiry = %v, want %v", c.nextExpiry, want)
	}

	// At its exact expires time a rule no longer matches.
	c = mustCompile(t, `{"id":"x","kind":"ip","match":"192.0.2.2","expires":"2026-11-15T04:00:00Z"}
`, time.Date(2026, 11, 15, 4, 0, 0, 0, time.UTC))
	if matchID(c, "192.0.2.2", "/", "", "") != "" {
		t.Errorf("rule matched at its expires time")
	}
}
