package bantasy

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

type handlerFixture struct {
	b      *Bantasy
	clock  *fakeClock
	logs   interface{ String() string }
	passed int
}

func newFixture(t *testing.T, rules string, configure func(*Config)) *handlerFixture {
	t.Helper()

	f := &handlerFixture{clock: &fakeClock{t: t0}, logs: captureLog(t)}

	path := tempPath(t, "rules.jsonl")
	writeFile(t, path, rules)

	cfg := CreateConfig()
	cfg.Files = []string{path}

	if configure != nil {
		configure(cfg)
	}

	next := http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) {
		f.passed++
		rw.WriteHeader(http.StatusOK)
	})

	b, err := newBantasy(next, cfg, "test", f.clock.now)
	if err != nil {
		t.Fatal(err)
	}

	f.b = b

	return f
}

// serve sends a request and returns the response status.
func (f *handlerFixture) serve(remote, uri string, header map[string]string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, "http://example.com"+uri, nil)
	req.RemoteAddr = remote

	for k, v := range header {
		req.Header.Set(k, v)
	}

	rec := httptest.NewRecorder()
	f.b.ServeHTTP(rec, req)

	return rec
}

// logEvents returns the log lines with the given event field.
func logEvents(t *testing.T, logs, event string) []map[string]any {
	t.Helper()

	var out []map[string]any

	for _, line := range strings.Split(strings.TrimSpace(logs), "\n") {
		if line == "" {
			continue
		}

		ev := map[string]any{}
		if err := json.Unmarshal([]byte(line), &ev); err != nil {
			t.Fatalf("log line is not JSON: %q", line)
		}

		if ev["event"] == event {
			out = append(out, ev)
		}
	}

	return out
}

func TestServeBlockAndPass(t *testing.T) {
	f := newFixture(t, `{"id":"repo:php","kind":"path","match":"\\.php$","reason":"PHP scanner","cause":"sig:1"}`+"\n",
		func(c *Config) {
			c.StatusCode = http.StatusTeapot
			c.Body = "go away"
		})

	rec := f.serve("192.0.2.1:1234", "/index.php", nil)

	if rec.Code != http.StatusTeapot || rec.Body.String() != "go away" {
		t.Errorf("block response = %d %q", rec.Code, rec.Body.String())
	}

	if f.passed != 0 {
		t.Error("a blocked request reached next")
	}

	rec = f.serve("192.0.2.1:1234", "/index.html", nil)
	if rec.Code != http.StatusOK || f.passed != 1 {
		t.Errorf("clean request: code %d, passed %d", rec.Code, f.passed)
	}

	blocks := logEvents(t, f.logs.String(), "block")
	if len(blocks) != 1 {
		t.Fatalf("want 1 block log line, got %d: %s", len(blocks), f.logs)
	}

	want := map[string]any{
		"id": "repo:php", "cause": "sig:1", "kind": "path", "action": "block",
		"clientIp": "192.0.2.1", "uri": "/index.php", "reason": "PHP scanner",
	}
	for k, v := range want {
		if blocks[0][k] != v {
			t.Errorf("block log %s = %v, want %v", k, blocks[0][k], v)
		}
	}
}

func TestServeDefaultResponse(t *testing.T) {
	f := newFixture(t, `{"kind":"ip","match":"192.0.2.1"}`+"\n", func(c *Config) { c.LogBlocks = false })

	rec := f.serve("192.0.2.1:1", "/", nil)
	if rec.Code != http.StatusForbidden || rec.Body.Len() != 0 {
		t.Errorf("default block = %d %q, want 403 and no body", rec.Code, rec.Body.String())
	}

	if len(logEvents(t, f.logs.String(), "block")) != 0 {
		t.Error("logBlocks false still logged a block")
	}
}

func TestServeTrapBan(t *testing.T) {
	f := newFixture(t, `{"id":"repo:admin-probe","kind":"path","match":"^/wp-admin","action":"ban-ip","banSeconds":60}
{"id":"repo:office","kind":"ip","match":"198.51.100.0/24","action":"allow"}
{"id":"ops:ban","kind":"ip","match":"192.0.2.5"}
`, nil)

	if rec := f.serve("192.0.2.1:1", "/wp-admin/", nil); rec.Code != http.StatusForbidden {
		t.Fatalf("trap path: code %d, want 403", rec.Code)
	}

	if rec := f.serve("192.0.2.1:1", "/", nil); rec.Code != http.StatusForbidden {
		t.Errorf("clean path after trap: code %d, want 403", rec.Code)
	}

	if rec := f.serve("192.0.2.2:1", "/", nil); rec.Code != http.StatusOK {
		t.Errorf("other IP: code %d, want 200", rec.Code)
	}

	f.clock.advance(60 * time.Second)

	if rec := f.serve("192.0.2.1:1", "/", nil); rec.Code != http.StatusOK {
		t.Errorf("after banSeconds: code %d, want 200", rec.Code)
	}

	// An ip rule sets no trap ban.
	f.serve("192.0.2.5:1", "/wp-admin/", nil)
	f.serve("192.0.2.5:1", "/", nil)

	// An allowed IP is never trap-banned.
	if rec := f.serve("198.51.100.7:1", "/wp-admin/", nil); rec.Code != http.StatusOK {
		t.Errorf("allowed IP on trap path: code %d, want 200", rec.Code)
	}

	traps := logEvents(t, f.logs.String(), "trap")
	if len(traps) != 1 {
		t.Fatalf("want 1 trap line, got %d: %s", len(traps), f.logs)
	}

	if traps[0]["clientIp"] != "192.0.2.1" || traps[0]["id"] != "repo:admin-probe" || traps[0]["banSeconds"] != float64(60) {
		t.Errorf("trap line = %v", traps[0])
	}

	blocks := logEvents(t, f.logs.String(), "block")

	got := make([]string, 0, len(blocks))
	for _, b := range blocks {
		got = append(got, fmt.Sprintf("%v %v %v", b["action"], b["id"], b["cause"]))
	}

	want := []string{
		"ban-ip repo:admin-probe <nil>",
		"trap-ban <nil> repo:admin-probe",
		"block ops:ban <nil>",
		"block ops:ban <nil>",
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Errorf("block lines:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
}

func TestServeIPBanIPRuleSetsNoTrap(t *testing.T) {
	f := newFixture(t, `{"id":"ip","kind":"ip","match":"192.0.2.1","action":"ban-ip"}`+"\n", nil)

	if rec := f.serve("192.0.2.1:1", "/", nil); rec.Code != http.StatusForbidden {
		t.Errorf("code %d, want 403", rec.Code)
	}

	if traps := logEvents(t, f.logs.String(), "trap"); len(traps) != 0 {
		t.Errorf("an ip rule set a trap ban: %v", traps)
	}
}

func TestServeTrapBanDefaultSeconds(t *testing.T) {
	f := newFixture(t, `{"id":"trap","kind":"path","match":"^/trap","action":"ban-ip"}`+"\n",
		func(c *Config) { c.TrapBanSeconds = 120 })

	f.serve("192.0.2.1:1", "/trap", nil)

	traps := logEvents(t, f.logs.String(), "trap")
	if len(traps) != 1 || traps[0]["banSeconds"] != float64(120) {
		t.Errorf("trap lines = %v, want one with banSeconds 120", traps)
	}
}

func TestServeMatchesDecodedPath(t *testing.T) {
	f := newFixture(t, `{"kind":"path","match":"\\.php($|\\?)"}`+"\n", nil)

	for _, uri := range []string{"/index%2Ephp", "/index.php?a=1", "/index%2ephp?a=1"} {
		if rec := f.serve("192.0.2.1:1", uri, nil); rec.Code != http.StatusForbidden {
			t.Errorf("%s: code %d, want 403", uri, rec.Code)
		}
	}
}

func TestServeClientIPHeader(t *testing.T) {
	f := newFixture(t, `{"kind":"ip","match":"203.0.113.7"}`+"\n",
		func(c *Config) { c.ClientIPHeader = "X-Real-Ip" })

	tests := []struct {
		name, remote, header string
		want                 int
	}{
		{"header used", "10.0.0.1:1", "203.0.113.7", http.StatusForbidden},
		{"first token of a list", "10.0.0.1:1", "203.0.113.7, 10.0.0.2", http.StatusForbidden},
		{"header beats RemoteAddr", "203.0.113.7:1", "192.0.2.1", http.StatusOK},
		{"missing header falls back", "203.0.113.7:1", "", http.StatusForbidden},
		{"bad header falls back", "203.0.113.7:1", "not-an-ip", http.StatusForbidden},
		{"mapped IPv6 is unmapped", "10.0.0.1:1", "::ffff:203.0.113.7", http.StatusForbidden},
		{"IPv6 RemoteAddr", "[2001:db8::1]:443", "", http.StatusOK},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := map[string]string{}
			if tt.header != "" {
				h["X-Real-Ip"] = tt.header
			}

			if rec := f.serve(tt.remote, "/", h); rec.Code != tt.want {
				t.Errorf("code %d, want %d", rec.Code, tt.want)
			}
		})
	}
}

func TestNewSharesRuleSet(t *testing.T) {
	captureLog(t)

	a, b := tempPath(t, "a.jsonl"), tempPath(t, "b.jsonl")
	writeFile(t, a, `{"kind":"path","match":"^/trap","action":"ban-ip"}`+"\n")

	next := http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) { rw.WriteHeader(http.StatusOK) })

	newHandler := func(name string, files []string, trapBanMax int) http.Handler {
		cfg := CreateConfig()
		cfg.Files = files
		cfg.TrapBanMax = trapBanMax

		h, err := New(context.Background(), next, cfg, name)
		if err != nil {
			t.Fatal(err)
		}

		return h
	}

	serve := func(h http.Handler, uri string) int {
		req := httptest.NewRequest(http.MethodGet, uri, nil)
		req.RemoteAddr = "192.0.2.9:1"
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)

		return rec.Code
	}

	h1 := newHandler("one", []string{a, b}, 10)
	sameFilesOtherOrder := newHandler("two", []string{b, a}, 10)
	otherMax := newHandler("three", []string{a, b}, 20)

	// A trap on one middleware bans the IP on another with the same config.
	serve(h1, "/trap")

	if code := serve(sameFilesOtherOrder, "/"); code != http.StatusForbidden {
		t.Errorf("same files, other order: code %d, want 403", code)
	}

	if code := serve(otherMax, "/"); code != http.StatusOK {
		t.Errorf("other trapBanMax shares the trap-ban table: code %d, want 200", code)
	}
}

func TestNewValidatesConfig(t *testing.T) {
	tests := []struct {
		name string
		edit func(*Config)
	}{
		{"no files", func(c *Config) { c.Files = nil }},
		{"bad status", func(c *Config) { c.StatusCode = 99 }},
		{"negative reload", func(c *Config) { c.ReloadSeconds = -1 }},
		{"zero trapBanSeconds", func(c *Config) { c.TrapBanSeconds = 0 }},
		{"zero trapBanMax", func(c *Config) { c.TrapBanMax = 0 }},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := CreateConfig()
			cfg.Files = []string{"/nonexistent/rules.jsonl"}
			tt.edit(cfg)

			if _, err := New(context.Background(), http.NotFoundHandler(), cfg, "x"); err == nil {
				t.Error("want an error")
			}
		})
	}
}
