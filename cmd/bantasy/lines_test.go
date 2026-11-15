package main

import (
	"testing"
	"time"
)

var t0 = time.Date(2026, 11, 15, 3, 0, 0, 0, time.UTC)

func at(d time.Duration) *time.Time {
	t := t0.Add(d)
	return &t
}

func texts(lines []line) []string {
	out := make([]string, 0, len(lines))
	for _, l := range lines {
		out = append(out, l.text)
	}

	return out
}

func equal(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}

	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}

	return true
}

func TestParseLinesKeepsTextAndDropsBlankLines(t *testing.T) {
	text := "not json\n\n  \n{\"id\": \"x\",  \"kind\": \"ip\", \"match\": \"203.0.113.7\"}\n{\"kind\":5}\n"
	lines := parseLines(text)

	want := []string{"not json", `{"id": "x",  "kind": "ip", "match": "203.0.113.7"}`, `{"kind":5}`}
	if !equal(texts(lines), want) {
		t.Fatalf("got %q", texts(lines))
	}

	if lines[0].rec != nil || lines[1].id() != "x" || lines[2].rec != nil {
		t.Errorf("records: %+v", lines)
	}

	if got := render(parseLines("a\nb")); got != "a\nb\n" {
		t.Errorf("render = %q", got)
	}
}

func TestUpsertAppends(t *testing.T) {
	lines := upsert(parseLines("not json\n"), &record{ID: "ops:ip:45.33.32.7", Kind: "ip", Match: "45.33.32.7", Added: at(0)})

	want := []string{"not json", `{"id":"ops:ip:45.33.32.7","kind":"ip","match":"45.33.32.7","added":"2026-11-15T03:00:00Z"}`}
	if !equal(texts(lines), want) {
		t.Errorf("got %q", texts(lines))
	}
}

func TestUpsertReplacesInPlaceAndKeepsAdded(t *testing.T) {
	text := `{"id":"a","kind":"ip","match":"45.33.32.7","reason":"spam","added":"2026-11-01T00:00:00Z"}
{"kind":"user-agent","match":"curl"}
{"id":"a","kind":"ip","match":"45.33.32.7","reason":"dup"}
`
	lines := upsert(parseLines(text), &record{ID: "a", Kind: "ip", Match: "45.33.32.7", Reason: "still at it", Added: at(time.Hour)})

	want := []string{
		`{"id":"a","kind":"ip","match":"45.33.32.7","reason":"still at it","added":"2026-11-01T00:00:00Z"}`,
		`{"kind":"user-agent","match":"curl"}`,
	}
	if !equal(texts(lines), want) {
		t.Errorf("got %q", texts(lines))
	}
}

func TestRemoveIDs(t *testing.T) {
	text := "{\"id\":\"a\",\"kind\":\"ip\",\"match\":\"45.33.32.7\"}\nnot json\n{\"id\":\"b\",\"kind\":\"ip\",\"match\":\"81.2.69.0/24\"}\n"

	lines, found := removeIDs(parseLines(text), []string{"a", "c"})
	if !equal(texts(lines), []string{"not json", `{"id":"b","kind":"ip","match":"81.2.69.0/24"}`}) {
		t.Errorf("got %q", texts(lines))
	}

	if !found["a"] || found["c"] || len(found) != 1 {
		t.Errorf("found = %v", found)
	}
}

func TestPruneDropsOnlyExpired(t *testing.T) {
	lines := []line{
		{text: "permanent", rec: &record{}},
		{text: "expired", rec: &record{Expires: at(0)}},
		{text: "live", rec: &record{Expires: at(time.Second)}},
		{text: "not json"},
	}

	if got := texts(prune(lines, t0)); !equal(got, []string{"permanent", "live", "not json"}) {
		t.Errorf("got %q", got)
	}
}
