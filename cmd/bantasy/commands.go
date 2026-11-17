package main

import (
	"errors"
	"fmt"
	"net/netip"
	"os"
	"strings"
	"text/tabwriter"
	"time"
	"unicode"
)

const (
	defaultSource = "ops"
	defaultIPTTL  = 24 * time.Hour
	dynamicRef    = "traefik/bantasy-dynamic:dynamic.jsonl"
	staticRef     = "traefik/bantasy-static:static.jsonl"
)

// targets returns the --file targets, then the --configmap targets, each in
// command-line order, or defaults when neither flag is given.
func targets(o *options, e env, defaults ...string) ([]target, error) {
	refs := []string(o.configMaps)
	if len(o.files) == 0 && len(refs) == 0 {
		refs = defaults
	}

	out := make([]target, 0, len(o.files)+len(refs))

	for _, f := range o.files {
		out = append(out, &fileTarget{path: f})
	}

	seen := map[string]bool{}

	for _, ref := range refs {
		t, err := parseConfigMapRef(ref)
		if err != nil {
			return nil, &usageError{msg: err.Error()}
		}

		// Two targets in one ConfigMap hold one resourceVersion, so the
		// second write would always conflict.
		cm := t.namespace + "/" + t.configMap
		if seen[cm] {
			return nil, usagef("--configmap names %s twice; use one key per ConfigMap", cm)
		}

		seen[cm] = true

		t.context = o.context
		t.kubectl = e.kubectl
		out = append(out, t)
	}

	return out, nil
}

// edit is one target, its text as read, and its new lines.
type edit struct {
	t     target
	text  string
	lines []line
}

// readTargets reads every target before any write, so a refused command
// writes nothing.
func readTargets(o *options, e env, defaults ...string) ([]*edit, error) {
	ts, err := targets(o, e, defaults...)
	if err != nil {
		return nil, err
	}

	out := make([]*edit, 0, len(ts))

	for _, t := range ts {
		text, err := t.read()
		if err != nil {
			return nil, fmt.Errorf("%s: %w", t.name(), err)
		}

		out = append(out, &edit{t: t, text: text, lines: parseLines(text)})
	}

	return out, nil
}

// writeAll drops the expired lines of each target and writes each changed
// target in turn. It stops at the first error; the targets before it stay
// written.
func writeAll(cmd string, edits []*edit, at time.Time, e env) error {
	wrote := false

	for _, ed := range edits {
		text := render(prune(ed.lines, at))
		if text == ed.text {
			e.outf("%s: %s: no change\n", cmd, ed.t.name())
			continue
		}

		if err := ed.t.write(text); err != nil {
			err = fmt.Errorf("%s: %w", ed.t.name(), err)
			if wrote {
				err = fmt.Errorf("%w (the targets before it are written)", err)
			}

			return err
		}

		wrote = true

		e.outf("%s: %s: done\n", cmd, ed.t.name())
	}

	return nil
}

func now(e env) time.Time {
	return e.now().UTC().Truncate(time.Second)
}

func sourceOf(o *options) string {
	if o.source == "" {
		return defaultSource
	}

	return o.source
}

func runAdd(pos []string, o *options, e env) error {
	at := now(e)

	recs, err := addRecords(pos, o, at)
	if err != nil {
		return err
	}

	edits, err := readTargets(o, e, dynamicRef)
	if err != nil {
		return err
	}

	for _, ed := range edits {
		// Prune first, so a rule that has expired is added anew, with a new
		// added time.
		ed.lines = prune(ed.lines, at)
		for _, r := range recs {
			c := *r
			ed.lines = upsert(ed.lines, &c)
		}
	}

	return writeAll("add", edits, at, e)
}

// addRecords checks the add arguments and builds one record per match.
func addRecords(pos []string, o *options, at time.Time) ([]*record, error) {
	if len(pos) < 2 {
		return nil, usagef("add needs a kind and at least one match")
	}

	if strings.TrimSpace(o.reason) == "" {
		return nil, usagef("add needs --reason")
	}

	if o.set["id"] && len(pos) != 2 {
		return nil, usagef("--id needs exactly one match")
	}

	kind := pos[0]

	action, err := actionOf(o)
	if err != nil {
		return nil, err
	}

	ttl, err := ttlOf(kind, o)
	if err != nil {
		return nil, err
	}

	var expires *time.Time

	if ttl > 0 {
		t := at.Add(ttl)
		expires = &t
	}

	recs := make([]*record, 0, len(pos)-1)

	for _, text := range pos[1:] {
		m, err := normaliseMatch(kind, text)
		if err != nil {
			return nil, err
		}

		id := o.id
		if id == "" {
			id = ruleID(sourceOf(o), kind, m)
		}

		recs = append(recs, &record{
			ID: id, Kind: kind, Match: m, Action: action, Reason: o.reason,
			Source: sourceOf(o), Cause: o.cause, Added: &at, Expires: expires,
		})
	}

	return recs, nil
}

// actionOf is --action, or "" for block: the default is not written.
func actionOf(o *options) (string, error) {
	if o.action == "" || o.action == actionBlock {
		return "", nil
	}

	return o.action, checkAction(o.action)
}

// ttlOf is --ttl, or the default for kind. 0 means no expiry.
func ttlOf(kind string, o *options) (time.Duration, error) {
	if o.set["ttl"] {
		return parseTTL(o.ttl)
	}

	if kind == kindIP {
		return defaultIPTTL, nil
	}

	return 0, nil
}

func runRemove(pos []string, o *options, e env) error {
	ids, err := removeArgs(pos, o)
	if err != nil {
		return err
	}

	edits, err := readTargets(o, e, dynamicRef)
	if err != nil {
		return err
	}

	found := map[string]bool{}

	for _, ed := range edits {
		var f map[string]bool

		ed.lines, f = removeIDs(ed.lines, ids)

		for id := range f {
			found[id] = true
		}
	}

	var missing []string

	for _, id := range ids {
		if !found[id] {
			missing = append(missing, id)
		}
	}

	if len(missing) > 0 {
		return fmt.Errorf("no target holds %s; nothing written", strings.Join(missing, ", "))
	}

	return writeAll("remove", edits, now(e), e)
}

// removeArgs returns the ids to remove: the arguments when the first holds
// ":", else the ids computed from a kind and matches.
func removeArgs(pos []string, o *options) ([]string, error) {
	if len(pos) == 0 {
		return nil, usagef("remove needs ids, or a kind and matches")
	}

	if strings.Contains(pos[0], ":") {
		if o.set["source"] {
			return nil, usagef("--source applies only to remove <kind> <match>...")
		}

		return pos, nil
	}

	if len(pos) < 2 {
		return nil, usagef("remove %s needs at least one match", pos[0])
	}

	ids := make([]string, 0, len(pos)-1)

	for _, text := range pos[1:] {
		m, err := normaliseMatch(pos[0], text)
		if err != nil {
			return nil, err
		}

		ids = append(ids, ruleID(sourceOf(o), pos[0], m))
	}

	return ids, nil
}

func runPrune(pos []string, o *options, e env) error {
	if len(pos) > 0 {
		return usagef("prune takes no arguments")
	}

	edits, err := readTargets(o, e, dynamicRef)
	if err != nil {
		return err
	}

	return writeAll("prune", edits, now(e), e)
}

func runList(pos []string, o *options, e env) error {
	if len(pos) > 0 {
		return usagef("list takes no arguments")
	}

	edits, err := readTargets(o, e, dynamicRef, staticRef)
	if err != nil {
		return err
	}

	at := now(e)
	w := tabwriter.NewWriter(e.stdout, 0, 0, 2, ' ', 0)
	_, _ = fmt.Fprintln(w, "TARGET\tID\tKIND\tMATCH\tACTION\tSOURCE\tCAUSE\tEXPIRES")

	for _, ed := range edits {
		for _, l := range ed.lines {
			// A line with no kind is not a rule: bantasy never loads it.
			if l.rec != nil && l.rec.Kind != "" {
				_, _ = fmt.Fprintln(w, listRow(ed.t.name(), l.rec, at))
			}
		}
	}

	return w.Flush()
}

func listRow(name string, r *record, at time.Time) string {
	action := r.Action
	if action == "" {
		action = actionBlock
	}

	exp := "-"
	if r.Expires != nil {
		exp = r.Expires.UTC().Format(time.RFC3339)
		if !at.Before(*r.Expires) {
			exp = "expired"
		}
	}

	cells := []string{name, r.ID, r.Kind, r.Match, action, r.Source, r.Cause, exp}
	for i, c := range cells {
		// A tab or newline in a match would break the columns.
		c = strings.NewReplacer("\t", `\t`, "\n", `\n`).Replace(c)
		if c == "" {
			c = "-"
		}

		cells[i] = c
	}

	return strings.Join(cells, "\t")
}

// errBadLines is the error of check when a file has bad lines.
var errBadLines = errors.New("bad lines found")

func runCheck(pos []string, e env) error {
	if len(pos) == 0 {
		return usagef("check needs at least one file")
	}

	bad := 0

	for _, path := range pos {
		b, err := os.ReadFile(path) //nolint:gosec // reading the files the user names is the job
		if err != nil {
			return err
		}

		for _, msg := range checkText(string(b)) {
			e.outf("%s:%s\n", path, msg)
			bad++
		}
	}

	if bad > 0 {
		return fmt.Errorf("%w: %d", errBadLines, bad)
	}

	return nil
}

// checkText returns "<line>: <reason>" for each bad line. An unparsable
// last line with no newline counts as bad: a writer must end each line.
func checkText(text string) []string {
	var out []string

	for i, l := range strings.Split(text, "\n") {
		if strings.TrimSpace(l) == "" {
			continue
		}

		if _, err := checkLine([]byte(l)); err != nil {
			out = append(out, fmt.Sprintf("%d: %v", i+1, err))
		}
	}

	return out
}

func runIpinfo(pos []string, e env) error {
	if len(pos) != 1 {
		return usagef("ipinfo needs exactly one address")
	}

	addr, err := netip.ParseAddr(pos[0])
	if err != nil {
		return usagef("not an IP address: %q", pos[0])
	}

	// normaliseIP refuses a zone and the non-public ranges, which have no
	// RDAP record.
	if _, perr := normaliseIP(addr.String()); perr != nil {
		return &usageError{msg: perr.Error()}
	}

	n, err := e.rdap.lookup(addr)
	if err != nil {
		return err
	}

	w := tabwriter.NewWriter(e.stdout, 0, 0, 2, ' ', 0)
	field := func(k, v string) {
		if v != "" {
			_, _ = fmt.Fprintf(w, "%s\t%s\n", k, noControl(v))
		}
	}

	field("registry", n.url)
	field("name", n.name)

	var narrow []string

	for _, p := range n.cidrs {
		if _, err := normaliseIP(p.String()); err != nil {
			field("cidr", p.String()+" ("+refusal(p)+")")
			continue
		}

		field("cidr", p.String())
		narrow = append(narrow, p.String())
	}

	field("country", n.country)
	field("org", n.org)
	field("abuse", n.abuse)

	if err := w.Flush(); err != nil {
		return err
	}

	e.outf("\nRDAP shows the registrant, not the location or the end user.\n\n")

	if len(narrow) == 0 {
		e.outf("# block too wide for add: narrow the CIDR by hand\n")
		return nil
	}

	reason := n.name
	if reason == "" {
		reason = n.org
	}

	if reason == "" {
		reason = "RDAP " + addr.String()
	}

	e.outf("bantasy add ip %s --reason %s\n", strings.Join(narrow, " "), shellQuote(noControl(reason)))

	return nil
}

// refusal says why add refuses p: it overlaps a non-public range, or it is
// too wide.
func refusal(p netip.Prefix) string {
	minBits := minBits6
	if p.Addr().Is4() {
		minBits = minBits4
	}

	if p.Bits() < minBits {
		return "too wide for add"
	}

	return "not public, not for add"
}

// noControl replaces each control character with "?". RDAP text comes from
// a remote server, and a newline or an escape sequence would break the
// output or the add command.
func noControl(s string) string {
	return strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return '?'
		}

		return r
	}, s)
}

// shellQuote quotes s for a POSIX shell.
func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// pardonID is the id of the pardon for match. It is not ruleID: that is the
// id of the ban on the same match, and the pardon would replace it.
func pardonID(source, match string) string {
	return source + ":" + actionPardon + ":" + match
}

// runUnban removes the bans with each match and writes a pardon for it.
func runUnban(pos []string, o *options, e env) error {
	// Not now(e): a pardon must lift a trap ban set earlier in the same second.
	at := e.now().UTC()

	matches, prefixes, err := unbanMatches(pos)
	if err != nil {
		return err
	}

	ttl, err := ttlOf(kindIP, o)
	if err != nil {
		return err
	}

	var expires *time.Time

	if ttl > 0 {
		t := at.Add(ttl)
		expires = &t
	}

	edits, err := readTargets(o, e, dynamicRef)
	if err != nil {
		return err
	}

	scan := edits
	if len(o.files) == 0 && len(o.configMaps) == 0 {
		scan = append(scan[:len(scan):len(scan)], readStatic(o, e)...)
	}

	removed := map[*edit][]string{}

	for _, ed := range edits {
		ed.lines = prune(ed.lines, at)

		for i, m := range matches {
			var r []string

			ed.lines, r = removeIPBlocks(ed.lines, prefixes[i])
			removed[ed] = append(removed[ed], r...)

			// removeIDs, not upsert: upsert keeps the old added time, and a
			// second unban must lift the bans set since the first.
			id := pardonID(sourceOf(o), m)
			ed.lines, _ = removeIDs(ed.lines, []string{id})
			ed.lines = append(ed.lines, newLine(&record{
				ID: id, Kind: kindIP, Match: m, Action: actionPardon, Reason: o.reason,
				Source: sourceOf(o), Cause: o.cause, Added: &at, Expires: expires,
			}))
		}
	}

	if err := writeAll("unban", edits, at, e); err != nil {
		return err
	}

	for _, ed := range edits {
		for _, label := range removed[ed] {
			e.outf("unban: %s: removed %s\n", ed.t.name(), label)
		}
	}

	warnStillBlocked(matches, prefixes, scan, e, at)

	return nil
}

// unbanMatches parses the unban arguments and drops repeats. It returns
// each match and its prefix. It does not refuse non-public or wide ranges,
// as add does: a pardon never blocks, and a trap can ban any client IP.
func unbanMatches(pos []string) ([]string, []netip.Prefix, error) {
	if len(pos) == 0 {
		return nil, nil, usagef("unban needs at least one ip or cidr")
	}

	var (
		matches  []string
		prefixes []netip.Prefix
	)

	seen := map[string]bool{}

	for _, text := range pos {
		p, err := parseIPMatch(text)
		if err != nil {
			return nil, nil, err
		}

		m := ipMatch(p)
		if seen[m] {
			continue
		}

		seen[m] = true
		matches = append(matches, m)
		prefixes = append(prefixes, p)
	}

	return matches, prefixes, nil
}

// readStatic reads the static rule file for the unban warnings. A failed
// read is a warning, not a failure: the unban still has value.
func readStatic(o *options, e env) []*edit {
	st, err := readTargets(o, e, staticRef)
	if err != nil {
		e.errf("unban: warning: %v; static rules not checked\n", err)
		return nil
	}

	return st
}

// warnStillBlocked prints a warning for each unexpired ban or trap rule in
// scan that overlaps a match. The static rule file is not pruned, so the
// expiry check matters there.
func warnStillBlocked(matches []string, prefixes []netip.Prefix, scan []*edit, e env, at time.Time) {
	for _, ed := range scan {
		for _, l := range ed.lines {
			if l.expired(at) || !l.blocksIP() {
				continue
			}

			q, err := parseIPMatch(l.rec.Match)
			if err != nil {
				continue
			}

			for i, p := range prefixes {
				if p.Overlaps(q) {
					e.errf("unban: warning: %s: %s still blocks %s\n", ed.t.name(), l.label(), matches[i])
				}
			}
		}
	}
}
