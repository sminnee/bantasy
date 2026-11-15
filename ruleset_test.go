package bantasy

import (
	"net/netip"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

func ruleSetMatch(rs *ruleSet, ip string) string {
	r := rs.current().match(newRequest(netip.MustParseAddr(ip), "/", "", ""))
	if r == nil {
		return ""
	}

	return r.ID
}

func TestRuleSetMissingFile(t *testing.T) {
	logs := captureLog(t)
	clock := &fakeClock{t: t0}
	path := tempPath(t, "bans.jsonl")

	rs := newRuleSet([]string{path}, 10*time.Second, clock.now)
	if got := ruleSetMatch(rs, "192.0.2.1"); got != "" {
		t.Errorf("missing file matched %q", got)
	}

	if logs.Len() != 0 {
		t.Errorf("missing file logged: %s", logs)
	}

	// The file appears later.
	writeFile(t, path, `{"id":"a","kind":"ip","match":"192.0.2.1"}`+"\n")
	clock.advance(10 * time.Second)

	if got := ruleSetMatch(rs, "192.0.2.1"); got != "a" {
		t.Errorf("new file: got %q, want a", got)
	}
}

func TestRuleSetReloadInterval(t *testing.T) {
	captureLog(t)

	clock := &fakeClock{t: t0}
	path := tempPath(t, "bans.jsonl")
	writeFile(t, path, `{"id":"a","kind":"ip","match":"192.0.2.1"}`+"\n")

	rs := newRuleSet([]string{path}, 10*time.Second, clock.now)
	if got := ruleSetMatch(rs, "192.0.2.1"); got != "a" {
		t.Fatalf("got %q, want a", got)
	}

	writeFile(t, path, `{"id":"b","kind":"ip","match":"192.0.2.2"}`+"\n")

	clock.advance(9 * time.Second)

	if got := ruleSetMatch(rs, "192.0.2.1"); got != "a" {
		t.Errorf("before the interval: got %q, want the old rule a", got)
	}

	clock.advance(time.Second)

	if got := ruleSetMatch(rs, "192.0.2.2"); got != "b" {
		t.Errorf("after the interval: got %q, want b", got)
	}

	if got := ruleSetMatch(rs, "192.0.2.1"); got != "" {
		t.Errorf("removed rule still matches: %q", got)
	}

	// An unchanged file is not reparsed.
	parses := rs.files[0].parses

	for i := 0; i < 3; i++ {
		clock.advance(10 * time.Second)
		ruleSetMatch(rs, "192.0.2.2")
	}

	if rs.files[0].parses != parses {
		t.Errorf("unchanged file reparsed %d times", rs.files[0].parses-parses)
	}
}

func TestRuleSetAppendAndPartialLine(t *testing.T) {
	logs := captureLog(t)
	clock := &fakeClock{t: t0}
	path := tempPath(t, "bans.jsonl")
	writeFile(t, path, `{"id":"a","kind":"ip","match":"192.0.2.1"}`+"\n"+`{"id":"bad","kind":"ip","match":"nope"}`+"\n")

	rs := newRuleSet([]string{path}, time.Second, clock.now)

	if got := ruleSetMatch(rs, "192.0.2.1"); got != "a" {
		t.Errorf("a bad line blocked the file's other rules: got %q", got)
	}

	if !strings.Contains(logs.String(), `"level":"warn"`) || !strings.Contains(logs.String(), "line 2") {
		t.Errorf("no warning with the line number for the bad line: %s", logs)
	}

	logs.Reset()

	// A writer is part way through a line.
	appendFile(t, path, `{"id":"b","kind":"ip","ma`)
	clock.advance(time.Second)

	if got := ruleSetMatch(rs, "192.0.2.1"); got != "a" {
		t.Errorf("partial line: got %q, want a", got)
	}

	// The reparse warns again about line 2, but not about the partial line 3.
	if strings.Contains(logs.String(), "line 3") {
		t.Errorf("partial line logged a warning: %s", logs)
	}

	appendFile(t, path, `tch":"192.0.2.2"}`+"\n")
	clock.advance(time.Second)

	if got := ruleSetMatch(rs, "192.0.2.2"); got != "b" {
		t.Errorf("completed line: got %q, want b", got)
	}
}

func TestRuleSetExpiryWithoutFileChange(t *testing.T) {
	captureLog(t)

	clock := &fakeClock{t: t0}
	path := tempPath(t, "bans.jsonl")
	writeFile(t, path, `{"id":"a","kind":"ip","match":"192.0.2.1","expires":"2026-11-15T03:00:05Z"}`+"\n")

	rs := newRuleSet([]string{path}, time.Hour, clock.now)

	if got := ruleSetMatch(rs, "192.0.2.1"); got != "a" {
		t.Fatalf("got %q, want a", got)
	}

	parses := rs.files[0].parses

	clock.advance(5 * time.Second)

	if got := ruleSetMatch(rs, "192.0.2.1"); got != "" {
		t.Errorf("expired rule still matches")
	}

	if rs.files[0].parses != parses {
		t.Error("expiry reread the file")
	}
}

func TestRuleSetIgnoredSummary(t *testing.T) {
	logs := captureLog(t)
	path := tempPath(t, "bans.jsonl")
	writeFile(t, path, `{"kind":"email-domain","match":"a.example"}
{"kind":"email-domain","match":"b.example"}
{"kind":"ip","match":"192.0.2.1","action":"signal"}
{"kind":"ip","match":"192.0.2.2"}
`)

	newRuleSet([]string{path}, time.Second, (&fakeClock{t: t0}).now)

	lines := strings.Split(strings.TrimSpace(logs.String()), "\n")
	if len(lines) != 1 {
		t.Fatalf("want one summary line, got %d: %s", len(lines), logs)
	}

	if !strings.Contains(lines[0], "loaded 1 rules, ignored action signal: 1, kind email-domain: 2") {
		t.Errorf("summary = %s", lines[0])
	}
}

func TestRuleSetMergesFiles(t *testing.T) {
	captureLog(t)

	a, b := tempPath(t, "patterns.jsonl"), tempPath(t, "bans.jsonl")
	writeFile(t, a, `{"id":"a","kind":"ip","match":"192.0.2.1"}`+"\n")
	writeFile(t, b, `{"id":"b","kind":"ip","match":"192.0.2.2"}`+"\n")

	rs := newRuleSet([]string{a, b}, time.Second, (&fakeClock{t: t0}).now)

	if ruleSetMatch(rs, "192.0.2.1") != "a" || ruleSetMatch(rs, "192.0.2.2") != "b" {
		t.Error("rules from both files do not match")
	}
}

func TestRuleSetDeletedFile(t *testing.T) {
	captureLog(t)

	clock := &fakeClock{t: t0}
	path := tempPath(t, "bans.jsonl")
	writeFile(t, path, `{"id":"a","kind":"ip","match":"192.0.2.1"}`+"\n")

	rs := newRuleSet([]string{path}, time.Second, clock.now)

	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}

	clock.advance(time.Second)

	if got := ruleSetMatch(rs, "192.0.2.1"); got != "" {
		t.Errorf("deleted file's rule still matches: %q", got)
	}
}

func TestRuleSetUnreadableFileKeepsRules(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root can read any file")
	}

	logs := captureLog(t)
	clock := &fakeClock{t: t0}
	path := tempPath(t, "bans.jsonl")
	writeFile(t, path, `{"id":"a","kind":"ip","match":"192.0.2.1"}`+"\n")

	rs := newRuleSet([]string{path}, time.Second, clock.now)

	appendFile(t, path, `{"id":"b","kind":"ip","match":"192.0.2.2"}`+"\n")

	if err := os.Chmod(path, 0); err != nil {
		t.Fatal(err)
	}

	clock.advance(time.Second)

	if got := ruleSetMatch(rs, "192.0.2.1"); got != "a" {
		t.Errorf("unreadable file lost its rules: got %q, want a", got)
	}

	if !strings.Contains(logs.String(), `"level":"error"`) {
		t.Errorf("no error logged: %s", logs)
	}
}

// TestRuleSetConcurrentReload runs requests across reloads. Run it with
// -race (make race) to check the locking.
func TestRuleSetConcurrentReload(t *testing.T) {
	captureLog(t)

	path := tempPath(t, "bans.jsonl")
	writeFile(t, path, `{"id":"a","kind":"ip","match":"192.0.2.1"}`+"\n")

	rs := newRuleSet([]string{path}, 0, time.Now)

	var wg sync.WaitGroup

	for g := 0; g < 8; g++ {
		wg.Add(1)

		go func() {
			defer wg.Done()

			for i := 0; i < 200; i++ {
				if got := ruleSetMatch(rs, "192.0.2.1"); got != "a" {
					t.Errorf("got %q, want a", got)

					return
				}
			}
		}()
	}

	for i := 0; i < 20; i++ {
		appendFile(t, path, `{"kind":"ip","match":"192.0.2.200"}`+"\n")
	}

	wg.Wait()
}
