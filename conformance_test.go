package bantasy

import (
	"os"
	"strings"
	"testing"
)

// readFixture returns the lines of cmd/bantasy/testdata/lines.jsonl and
// the verdict for each. The CLI's check reads the same fixture, so the two
// line checks stay in step.
func readFixture(t *testing.T) ([]string, []string) {
	t.Helper()

	lines, err := os.ReadFile("cmd/bantasy/testdata/lines.jsonl")
	if err != nil {
		t.Fatal(err)
	}

	want, err := os.ReadFile("cmd/bantasy/testdata/lines.want")
	if err != nil {
		t.Fatal(err)
	}

	l := strings.Split(strings.TrimSuffix(string(lines), "\n"), "\n")
	w := strings.Split(strings.TrimSuffix(string(want), "\n"), "\n")

	if len(l) != len(w) {
		t.Fatalf("fixture has %d lines and %d verdicts", len(l), len(w))
	}

	return l, w
}

func TestParseRuleMatchesTheCLIFixture(t *testing.T) {
	lines, want := readFixture(t)

	for i, line := range lines {
		_, ignored, err := parseRule([]byte(line))

		got := "ok"

		switch {
		case err != nil:
			got = "bad"
		case ignored != "":
			got = "ignored"
		}

		if got != want[i] {
			t.Errorf("line %d %s: got %s, want %s (err %v)", i+1, line, got, want[i], err)
		}
	}
}
