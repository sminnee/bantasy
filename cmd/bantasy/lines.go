package main

import (
	"encoding/json"
	"strings"
	"time"
)

// record is one rule. The field types are the reader's, so a line that
// decodes here decodes in bantasy too.
type record struct {
	ID         string     `json:"id,omitempty"`
	Kind       string     `json:"kind"`
	Match      string     `json:"match"`
	Action     string     `json:"action,omitempty"`
	BanSeconds int        `json:"banSeconds,omitempty"`
	Reason     string     `json:"reason,omitempty"`
	Source     string     `json:"source,omitempty"`
	Cause      string     `json:"cause,omitempty"`
	Added      *time.Time `json:"added,omitempty"`
	Expires    *time.Time `json:"expires,omitempty"`
}

// line is one non-blank line of a rule file. rec is nil when the text does
// not decode; such a line is kept as it is.
type line struct {
	text string
	rec  *record
}

func (l line) id() string {
	if l.rec == nil {
		return ""
	}

	return l.rec.ID
}

func (l line) expired(now time.Time) bool {
	return l.rec != nil && l.rec.Expires != nil && !now.Before(*l.rec.Expires)
}

// parseLines splits a rule file into lines. Blank lines drop.
func parseLines(text string) []line {
	var out []line

	for _, t := range strings.Split(text, "\n") {
		if strings.TrimSpace(t) == "" {
			continue
		}

		l := line{text: t}

		r := &record{}
		if json.Unmarshal([]byte(t), r) == nil {
			l.rec = r
		}

		out = append(out, l)
	}

	return out
}

// render joins the lines. Each line ends with "\n", so a line that a tool
// appends starts on a line of its own.
func render(lines []line) string {
	var b strings.Builder

	for _, l := range lines {
		b.WriteString(l.text)
		b.WriteByte('\n')
	}

	return b.String()
}

// prune drops the lines that have expired at now, of any writer.
func prune(lines []line, now time.Time) []line {
	out := make([]line, 0, len(lines))

	for _, l := range lines {
		if !l.expired(now) {
			out = append(out, l)
		}
	}

	return out
}

// newLine encodes r as a line.
func newLine(r *record) line {
	b, err := json.Marshal(r)
	if err != nil {
		// A record of strings, an int and times always encodes.
		panic(err)
	}

	return line{text: string(b), rec: r}
}

// upsert puts r in the place of the first line with its id, keeping that
// line's added time, and drops later lines with the id. With no such line,
// it appends r.
func upsert(lines []line, r *record) []line {
	out := make([]line, 0, len(lines)+1)
	done := false

	for _, l := range lines {
		if l.id() != r.ID {
			out = append(out, l)
			continue
		}

		if done {
			continue
		}

		if l.rec.Added != nil {
			r.Added = l.rec.Added
		}

		out = append(out, newLine(r))
		done = true
	}

	if !done {
		out = append(out, newLine(r))
	}

	return out
}

// removeIDs drops the lines with any of ids. found holds the ids it dropped.
func removeIDs(lines []line, ids []string) ([]line, map[string]bool) {
	want := map[string]bool{}
	for _, id := range ids {
		want[id] = true
	}

	found := map[string]bool{}
	out := make([]line, 0, len(lines))

	for _, l := range lines {
		if id := l.id(); id != "" && want[id] {
			found[id] = true
			continue
		}

		out = append(out, l)
	}

	return out, found
}
