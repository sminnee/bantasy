package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const (
	dynamic = "traefik/bantasy-dynamic"
	static  = "traefik/bantasy-static"
	dynKey  = "dynamic.jsonl"
)

var foreign = []string{
	`{"kind":"ip","match":"203.0.113.7","action":"ban-ip","banSeconds":3600}`,
	`{"id": "x", "kind": "email-domain", "match": "curl.com", "action": "smartypants:block-signup"}`,
	"not json at all",
}

// fakeKubectl holds ConfigMaps in memory, keyed by <namespace>/<name>.
type fakeKubectl struct {
	t          *testing.T
	configMaps map[string]map[string]any
	// writes lists each create or replace as "<verb> <namespace>/<name>".
	writes []string
	// contexts lists the --context of each call, "" for none.
	contexts []string
	// conflict names the ConfigMaps whose next write fails as a conflict.
	conflict map[string]bool
	// getErr is the stderr of a failed get, by ConfigMap.
	getErr map[string]string
}

func newFake(t *testing.T) *fakeKubectl {
	t.Helper()

	return &fakeKubectl{t: t, configMaps: map[string]map[string]any{}, conflict: map[string]bool{}, getErr: map[string]string{}}
}

// put stores a ConfigMap with resourceVersion 7.
func (f *fakeKubectl) put(ref string, data map[string]string) {
	ns, name, _ := strings.Cut(ref, "/")

	d := map[string]any{}
	for k, v := range data {
		d[k] = v
	}

	f.configMaps[ref] = map[string]any{
		"apiVersion": "v1",
		"kind":       "ConfigMap",
		"metadata":   map[string]any{"name": name, "namespace": ns, "resourceVersion": "7"},
		"data":       d,
	}
}

func (f *fakeKubectl) data(ref, key string) string {
	f.t.Helper()

	cm, ok := f.configMaps[ref]
	if !ok {
		f.t.Fatalf("no ConfigMap %s", ref)
	}

	s, _ := cm["data"].(map[string]any)[key].(string)

	return s
}

// lines returns the lines of the default write target.
func (f *fakeKubectl) lines() []string {
	return strings.Split(strings.TrimSuffix(f.data(dynamic, dynKey), "\n"), "\n")
}

var errExit = errors.New("exit status 1")

func (f *fakeKubectl) run(stdin string, args ...string) (string, string, error) {
	ctx := ""
	if len(args) > 1 && args[0] == "--context" {
		ctx = args[1]
		args = args[2:]
	}

	f.contexts = append(f.contexts, ctx)

	switch {
	case len(args) == 7 && args[0] == "get" && args[1] == "configmap":
		if msg, ok := f.getErr[args[4]+"/"+args[2]]; ok {
			return "", msg, errExit
		}

		cm, ok := f.configMaps[args[4]+"/"+args[2]]
		if !ok {
			return "", `Error from server (NotFound): configmaps "` + args[2] + `" not found`, errExit
		}

		b, err := json.Marshal(cm)
		if err != nil {
			f.t.Fatal(err)
		}

		return string(b), "", nil
	case len(args) == 3 && (args[0] == "create" || args[0] == "replace"):
		return f.write(args[0], stdin)
	}

	f.t.Fatalf("unexpected kubectl %q", args)

	return "", "", nil
}

func (f *fakeKubectl) write(verb, stdin string) (string, string, error) {
	var obj map[string]any
	if err := json.Unmarshal([]byte(stdin), &obj); err != nil {
		f.t.Fatalf("%s: %v", verb, err)
	}

	md, _ := obj["metadata"].(map[string]any)
	ref, _ := md["namespace"].(string)
	name, _ := md["name"].(string)
	ref += "/" + name

	if f.conflict[ref] {
		if verb == "create" {
			return "", `Error from server (AlreadyExists): configmaps "` + name + `" already exists`, errExit
		}

		return "", `Error from server (Conflict): Operation cannot be fulfilled on configmaps "` + name +
			`": the object has been modified; please apply your changes to the latest version and try again`, errExit
	}

	_, exists := f.configMaps[ref]
	if exists != (verb == "replace") {
		f.t.Fatalf("%s of %s, exists=%v", verb, ref, exists)
	}

	f.writes = append(f.writes, verb+" "+ref)
	f.configMaps[ref] = obj

	return "", "", nil
}

type result struct {
	code           int
	stdout, stderr string
}

func runWith(f *fakeKubectl, args ...string) result {
	var out, errOut bytes.Buffer

	e := env{stdout: &out, stderr: &errOut, now: func() time.Time { return t0 }, kubectl: f.run}
	code := run(args, e)

	return result{code: code, stdout: out.String(), stderr: errOut.String()}
}

func mustRun(t *testing.T, f *fakeKubectl, args ...string) result {
	t.Helper()

	r := runWith(f, args...)
	if r.code != 0 {
		t.Fatalf("bantasy %q: exit %d: %s", args, r.code, r.stderr)
	}

	return r
}

func decode(t *testing.T, line string) map[string]any {
	t.Helper()

	var m map[string]any
	if err := json.Unmarshal([]byte(line), &m); err != nil {
		t.Fatalf("%q: %v", line, err)
	}

	return m
}

func jsonl(lines ...string) string {
	return strings.Join(lines, "\n") + "\n"
}

func TestAddCreatesAMissingConfigMap(t *testing.T) {
	f := newFake(t)
	mustRun(t, f, "--context", "aws", "add", "email-domain", "X.com", "mailto.plus",
		"--reason", "spam", "--source", "smartypants", "--action", "smartypants:block-signup")

	if !equal(f.writes, []string{"create " + dynamic}) {
		t.Fatalf("writes = %q", f.writes)
	}

	if !strings.HasSuffix(f.data(dynamic, dynKey), "\n") {
		t.Error("text does not end with a newline")
	}

	want := []string{
		`{"id":"smartypants:email-domain:x.com","kind":"email-domain","match":"x.com","action":"smartypants:block-signup","reason":"spam","source":"smartypants","added":"2026-11-15T03:00:00Z"}`,
		`{"id":"smartypants:email-domain:mailto.plus","kind":"email-domain","match":"mailto.plus","action":"smartypants:block-signup","reason":"spam","source":"smartypants","added":"2026-11-15T03:00:00Z"}`,
	}
	if got := f.lines(); !equal(got, want) {
		t.Errorf("lines = %q", got)
	}

	for _, c := range f.contexts {
		if c != "aws" {
			t.Errorf("contexts = %q", f.contexts)
			break
		}
	}
}

func TestAddKeepsOtherLinesAndKeys(t *testing.T) {
	f := newFake(t)
	f.put(dynamic, map[string]string{dynKey: jsonl(foreign...), "other": "x.com\n"})

	mustRun(t, f, "add", "user-agent", "curl/8", "--reason", "scanner")

	if !equal(f.writes, []string{"replace " + dynamic}) {
		t.Fatalf("writes = %q", f.writes)
	}

	md, _ := f.configMaps[dynamic]["metadata"].(map[string]any)
	if md["resourceVersion"] != "7" {
		t.Errorf("resourceVersion = %v", md["resourceVersion"])
	}

	if got := f.data(dynamic, "other"); got != "x.com\n" {
		t.Errorf("other key = %q", got)
	}

	got := f.lines()
	if !equal(got[:3], foreign) || len(got) != 4 {
		t.Fatalf("lines = %q", got)
	}

	want := `{"id":"ops:user-agent:curl/8","kind":"user-agent","match":"curl/8","reason":"scanner","source":"ops","added":"2026-11-15T03:00:00Z"}`
	if got[3] != want {
		t.Errorf("rule = %s", got[3])
	}
}

func TestAddWithAListedIDReplacesTheLine(t *testing.T) {
	f := newFake(t)
	old := `{"id":"ops:ip:45.33.32.7","kind":"ip","match":"45.33.32.7","reason":"spam","source":"ops","added":"2026-11-01T00:00:00Z"}`
	f.put(dynamic, map[string]string{dynKey: jsonl(old, foreign[2])})

	// A host prefix normalises to the bare address, so it has the same id.
	mustRun(t, f, "add", "ip", "45.33.32.7/32", "--reason", "still spam", "--ttl", "7d")

	want := []string{
		`{"id":"ops:ip:45.33.32.7","kind":"ip","match":"45.33.32.7","reason":"still spam","source":"ops","added":"2026-11-01T00:00:00Z","expires":"2026-11-22T03:00:00Z"}`,
		foreign[2],
	}
	if got := f.lines(); !equal(got, want) {
		t.Errorf("lines = %q", got)
	}
}

// TestAddToEachTarget checks that each target keeps its own added time, and
// that --id replaces the computed id.
func TestAddToEachTarget(t *testing.T) {
	f := newFake(t)
	f.put("ns/one", map[string]string{"k": jsonl(`{"id":"mine","kind":"ip","match":"45.33.32.7","added":"2026-11-01T00:00:00Z"}`)})

	mustRun(t, f, "--configmap", "ns/one:k", "--configmap", "ns/two:k",
		"add", "ip", "45.33.32.7", "--reason", "r", "--ttl", "never", "--id", "mine")

	for ref, added := range map[string]string{"ns/one": "2026-11-01T00:00:00Z", "ns/two": "2026-11-15T03:00:00Z"} {
		want := `{"id":"mine","kind":"ip","match":"45.33.32.7","reason":"r","source":"ops","added":"` + added + `"}` + "\n"
		if got := f.data(ref, "k"); got != want {
			t.Errorf("%s = %q, want %q", ref, got, want)
		}
	}
}

func TestAddDefaultTTL(t *testing.T) {
	cases := []struct {
		args    []string
		expires any
	}{
		{[]string{"ip", "45.33.32.7"}, "2026-11-16T03:00:00Z"},
		{[]string{"user-agent", "sqlmap"}, nil},
		{[]string{"ip", "45.33.32.8", "--ttl", "never"}, nil},
		{[]string{"path", `^/wp-login\.php`, "--ttl", "30m"}, "2026-11-15T03:30:00Z"},
	}

	for _, c := range cases {
		f := newFake(t)
		mustRun(t, f, append(append([]string{"add"}, c.args...), "--reason", "r")...)

		if r := decode(t, f.lines()[0]); r["expires"] != c.expires {
			t.Errorf("%q: expires = %v, want %v", c.args, r["expires"], c.expires)
		}
	}
}

func TestRefusesBeforeAnyRead(t *testing.T) {
	cases := []struct {
		code int
		err  string
		args []string
	}{
		{1, "not a domain", []string{"add", "email-domain", "x.com", "pat@mailto.plus", "--reason", "r"}},
		{1, "not a public range", []string{"add", "ip", "10.0.0.1", "--reason", "r"}},
		{1, "bad TTL", []string{"add", "ip", "45.33.32.7", "--reason", "r", "--ttl", "1w"}},
		{1, `kind "cookie"`, []string{"add", "cookie", "x", "--reason", "r"}},
		{1, `action "nuke"`, []string{"add", "ip", "45.33.32.7", "--reason", "r", "--action", "nuke"}},
		{1, "not an IP address", []string{"remove", "ip", "nope"}},
		{2, "needs --reason", []string{"add", "ip", "45.33.32.7"}},
		{2, "exactly one match", []string{"add", "ip", "45.33.32.7", "45.33.32.8", "--reason", "r", "--id", "x"}},
		{2, "at least one match", []string{"add", "ip"}},
		{2, "does not take --reason", []string{"list", "--reason", "r"}},
		{2, "unknown command", []string{"frob"}},
		{2, "no command", []string{}},
		{2, "use <namespace>/<name>:<key>", []string{"--configmap", "bad", "list"}},
		{2, "names ns/a twice", []string{"--configmap", "ns/a:x", "--configmap", "ns/a:y", "prune"}},
	}

	for _, c := range cases {
		f := newFake(t)
		if r := runWith(f, c.args...); r.code != c.code || !strings.Contains(r.stderr, c.err) {
			t.Errorf("%q: exit %d, want %d; stderr %q, want %q", c.args, r.code, c.code, r.stderr, c.err)
		}

		if len(f.contexts) != 0 {
			t.Errorf("%q: kubectl ran", c.args)
		}
	}
}

func TestEveryWritePrunes(t *testing.T) {
	expired := `{"id":"other:ip:45.33.32.7","kind":"ip","match":"45.33.32.7","expires":"2026-11-15T03:00:00Z"}`
	live := `{"kind":"ip","match":"45.33.32.8","expires":"2026-11-15T03:00:01Z"}`

	for args, n := range map[*[]string]int{
		{"add", "ip", "81.2.69.0/24", "--reason", "scanner"}: 3,
		{"prune"}:                       2,
		{"remove", "ops:ip:45.33.32.9"}: 1,
	} {
		f := newFake(t)
		f.put(dynamic, map[string]string{dynKey: jsonl(expired, live, `{"id":"ops:ip:45.33.32.9","kind":"ip","match":"45.33.32.9"}`)})
		mustRun(t, f, (*args)...)

		if got := f.lines(); got[0] != live || len(got) != n {
			t.Errorf("%q: lines = %q", args, got)
		}
	}
}

func TestRemove(t *testing.T) {
	ua := `{"id":"smartypants:user-agent:phantomjscloud.com","kind":"user-agent","match":"PhantomJsCloud.com"}`
	ip := `{"id":"ops:ip:81.2.69.0/24","kind":"ip","match":"81.2.69.0/24"}`

	f := newFake(t)
	f.put(dynamic, map[string]string{dynKey: jsonl(foreign[0], ua, foreign[1], ip, foreign[2])})

	mustRun(t, f, "remove", "user-agent", "PHANTOMJSCLOUD.COM", "--source", "smartypants")
	mustRun(t, f, "remove", "ip", "81.2.69.77/24")

	if got := f.lines(); !equal(got, foreign) {
		t.Errorf("lines = %q", got)
	}
}

func TestRemoveRefusesAnUnlistedRule(t *testing.T) {
	ip := `{"id":"ops:ip:81.2.69.0/24","kind":"ip","match":"81.2.69.0/24"}`

	// foreign[1] has the match curl.com under id "x": another writer's rule.
	for _, args := range [][]string{
		{"remove", "email-domain", "curl.com"},
		{"remove", "ops:ip:81.2.69.0/24", "ops:ip:45.33.32.7"},
	} {
		f := newFake(t)
		f.put(dynamic, map[string]string{dynKey: jsonl(append(foreign, ip)...)})

		if r := runWith(f, args...); r.code != 1 || !strings.Contains(r.stderr, "nothing written") {
			t.Errorf("%q: exit %d, stderr %q", args, r.code, r.stderr)
		}

		if len(f.writes) != 0 {
			t.Errorf("%q: writes = %q", args, f.writes)
		}
	}
}

func TestRemoveFromEachTargetThatHoldsIt(t *testing.T) {
	a := `{"id":"a:ip:45.33.32.7","kind":"ip","match":"45.33.32.7"}`
	b := `{"id":"b:ip:45.33.32.8","kind":"ip","match":"45.33.32.8"}`

	f := newFake(t)
	f.put("ns/one", map[string]string{"k": jsonl(a, b)})
	f.put("ns/two", map[string]string{"k": jsonl(b)})
	f.put("ns/three", map[string]string{"k": jsonl(foreign[2])})

	mustRun(t, f, "remove", "a:ip:45.33.32.7", "b:ip:45.33.32.8",
		"--configmap", "ns/one:k", "--configmap", "ns/two:k", "--configmap", "ns/three:k")

	if !equal(f.writes, []string{"replace ns/one", "replace ns/two"}) {
		t.Errorf("writes = %q", f.writes)
	}
}

func TestConflictStopsTheWrite(t *testing.T) {
	for _, exists := range []bool{true, false} {
		f := newFake(t)
		if exists {
			f.put("ns/one", map[string]string{"k": ""})
		}

		f.conflict["ns/one"] = true

		r := runWith(f, "--configmap", "ns/one:k", "--configmap", "ns/two:k", "add", "user-agent", "sqlmap", "--reason", "r")
		if r.code != 1 || !strings.Contains(r.stderr, "ns/one:k") || !strings.Contains(r.stderr, "run the command again") {
			t.Errorf("exists=%v: exit %d, stderr %q", exists, r.code, r.stderr)
		}

		if len(f.writes) != 0 {
			t.Errorf("exists=%v: writes = %q", exists, f.writes)
		}
	}
}

func TestConflictAfterAWrite(t *testing.T) {
	f := newFake(t)
	f.conflict["ns/two"] = true

	r := runWith(f, "--configmap", "ns/one:k", "--configmap", "ns/two:k", "add", "user-agent", "sqlmap", "--reason", "r")
	if r.code != 1 || !strings.Contains(r.stderr, "ns/two:k") || !strings.Contains(r.stderr, "targets before it are written") {
		t.Errorf("exit %d, stderr %q", r.code, r.stderr)
	}

	if !equal(f.writes, []string{"create ns/one"}) {
		t.Errorf("writes = %q", f.writes)
	}

	// With no change to ns/one, nothing was written before the conflict.
	r = runWith(f, "--configmap", "ns/one:k", "--configmap", "ns/two:k", "add", "user-agent", "sqlmap", "--reason", "r")
	if r.code != 1 || strings.Contains(r.stderr, "targets before it") {
		t.Errorf("second run: exit %d, stderr %q", r.code, r.stderr)
	}
}

// TestReadFailure checks that a failed get is not read as a missing
// ConfigMap.
func TestReadFailure(t *testing.T) {
	f := newFake(t)
	f.getErr["ns/two"] = `Error from server (Forbidden): configmaps "two" is forbidden`

	r := runWith(f, "--configmap", "ns/one:k", "--configmap", "ns/two:k", "add", "user-agent", "sqlmap", "--reason", "r")
	if r.code != 1 || !strings.Contains(r.stderr, "ns/two:k") || !strings.Contains(r.stderr, "Forbidden") {
		t.Errorf("exit %d, stderr %q", r.code, r.stderr)
	}

	if len(f.writes) != 0 {
		t.Errorf("writes = %q", f.writes)
	}
}

func TestList(t *testing.T) {
	f := newFake(t)
	if r := mustRun(t, f, "list"); strings.Count(r.stdout, "\n") != 1 || !strings.HasPrefix(r.stdout, "TARGET") {
		t.Errorf("empty list = %q", r.stdout)
	}

	f.put(dynamic, map[string]string{dynKey: jsonl(
		`{"id":"ops:ip:45.33.32.7","kind":"ip","match":"45.33.32.7","source":"ops","cause":"trap:wp","expires":"2026-11-16T03:00:00Z"}`,
		`{"kind":"ip","match":"45.33.32.8","expires":"2026-11-15T03:00:00Z"}`,
		"not json at all",
		"{}",
	)})
	f.put(static, map[string]string{"static.jsonl": jsonl(`{"id":"wp","kind":"path","match":"^/wp-","action":"ban-ip"}`)})

	r := mustRun(t, f, "list")
	got := strings.Split(strings.TrimSuffix(r.stdout, "\n"), "\n")

	want := [][]string{
		{"TARGET", "ID", "KIND", "MATCH", "ACTION", "SOURCE", "CAUSE", "EXPIRES"},
		{dynamic + ":" + dynKey, "ops:ip:45.33.32.7", "ip", "45.33.32.7", "block", "ops", "trap:wp", "2026-11-16T03:00:00Z"},
		{dynamic + ":" + dynKey, "-", "ip", "45.33.32.8", "block", "-", "-", "expired"},
		{static + ":static.jsonl", "wp", "path", "^/wp-", "ban-ip", "-", "-", "-"},
	}

	if len(got) != len(want) {
		t.Fatalf("list = %q", r.stdout)
	}

	for i := range want {
		if !equal(strings.Fields(got[i]), want[i]) {
			t.Errorf("row %d = %q, want %q", i, got[i], want[i])
		}
	}

	if len(f.writes) != 0 {
		t.Errorf("list wrote: %q", f.writes)
	}
}

func TestFileTarget(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bans.jsonl")

	mustRun(t, newFake(t), "add", "ip", "45.33.32.7", "--reason", "r", "--file", path)
	mustRun(t, newFake(t), "--file", path, "add", "user-agent", "sqlmap", "--reason", "r")

	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}

	if got := parseLines(string(b)); len(got) != 2 || got[0].id() != "ops:ip:45.33.32.7" || got[1].id() != "ops:user-agent:sqlmap" {
		t.Errorf("file = %q", b)
	}

	entries, _ := os.ReadDir(dir)
	if len(entries) != 1 {
		t.Errorf("dir holds %d files, want 1", len(entries))
	}
}

func TestFileTargetKeepsASymlink(t *testing.T) {
	dir := t.TempDir()
	dest := filepath.Join(dir, "dest.jsonl")
	link := filepath.Join(dir, "link.jsonl")

	if err := os.WriteFile(dest, nil, 0o600); err != nil {
		t.Fatal(err)
	}

	if err := os.Symlink(dest, link); err != nil {
		t.Fatal(err)
	}

	mustRun(t, newFake(t), "--file", link, "add", "user-agent", "sqlmap", "--reason", "r")

	if fi, err := os.Lstat(link); err != nil || fi.Mode()&os.ModeSymlink == 0 {
		t.Errorf("link is gone: %v", err)
	}

	if b, err := os.ReadFile(dest); err != nil || !strings.Contains(string(b), "ops:user-agent:sqlmap") {
		t.Errorf("dest file = %q, %v", b, err)
	}
}

func TestCheck(t *testing.T) {
	dir := t.TempDir()
	clean := filepath.Join(dir, "clean.jsonl")
	bad := filepath.Join(dir, "bad.jsonl")

	for path, text := range map[string]string{
		clean: jsonl(foreign[:2]...) + "\n",
		bad:   jsonl(foreign[0], `{"kind":"path","match":"(x"}`) + `{"kind":"ip"`,
	} {
		if err := os.WriteFile(path, []byte(text), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	f := newFake(t)
	mustRun(t, f, "check", clean)

	r := runWith(f, "check", clean, bad)
	if r.code != 1 {
		t.Errorf("exit %d", r.code)
	}

	lines := strings.Split(strings.TrimSuffix(r.stdout, "\n"), "\n")
	if len(lines) != 2 || !strings.HasPrefix(lines[0], bad+":2: bad regexp") || !strings.HasPrefix(lines[1], bad+":3: bad JSON") {
		t.Errorf("stdout = %q", r.stdout)
	}
}

// TestCheckLineMatchesTheFixture is the CLI half of the reader parity
// check; conformance_test.go in the plugin package is the other half.
func TestCheckLineMatchesTheFixture(t *testing.T) {
	lines, err := os.ReadFile("testdata/lines.jsonl")
	if err != nil {
		t.Fatal(err)
	}

	want, err := os.ReadFile("testdata/lines.want")
	if err != nil {
		t.Fatal(err)
	}

	l := strings.Split(strings.TrimSuffix(string(lines), "\n"), "\n")
	w := strings.Split(strings.TrimSuffix(string(want), "\n"), "\n")

	if len(l) != len(w) || len(l) == 0 {
		t.Fatalf("fixture has %d lines and %d verdicts", len(l), len(w))
	}

	for i, line := range l {
		ignored, err := checkLine([]byte(line))

		got := "ok"

		switch {
		case err != nil:
			got = "bad"
		case ignored != "":
			got = "ignored"
		}

		if got != w[i] {
			t.Errorf("line %d %s: got %s, want %s (err %v)", i+1, line, got, w[i], err)
		}
	}
}
