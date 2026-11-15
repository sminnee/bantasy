package bantasy

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"sort"
	"strings"
	"sync"
	"time"
)

// ruleFile is the state of one rule file at its last check.
type ruleFile struct {
	path    string
	exists  bool
	modTime time.Time
	size    int64
	rules   []*rule
	// parses counts the reads of this file, for tests.
	parses int
}

// ruleSet is the live rules from a list of rule files. It reloads lazily
// from the request path: the first request after the reload interval stats
// the files and reparses the changed ones. Other requests go on with the
// current snapshot. There are no background goroutines.
type ruleSet struct {
	reload time.Duration
	now    func() time.Time

	// reloadMu is held by the one request that refreshes the rule set.
	// It guards files.
	reloadMu sync.Mutex
	files    []*ruleFile

	mu        sync.RWMutex
	snapshot  *compiled
	nextCheck time.Time
}

func newRuleSet(files []string, reload time.Duration, now func() time.Time) *ruleSet {
	rs := &ruleSet{reload: reload, now: now}

	for _, p := range files {
		rs.files = append(rs.files, &ruleFile{path: p})
	}

	rs.reloadMu.Lock()
	rs.refresh(now())
	rs.reloadMu.Unlock()

	return rs
}

// current returns the snapshot to match against, refreshing it first when
// the reload interval or the earliest rule expiry has passed.
func (rs *ruleSet) current() *compiled {
	now := rs.now()

	rs.mu.RLock()
	c := rs.snapshot
	due := !now.Before(rs.nextCheck) || (!c.nextExpiry.IsZero() && !now.Before(c.nextExpiry))
	rs.mu.RUnlock()

	if !due || !rs.reloadMu.TryLock() {
		return c
	}

	rs.refresh(now)
	rs.reloadMu.Unlock()

	rs.mu.RLock()
	c = rs.snapshot
	rs.mu.RUnlock()

	return c
}

// refresh stats the files when the interval has passed, reparses the ones
// whose mtime or size changed, and recompiles when a file changed or a rule
// expired. The caller holds reloadMu.
func (rs *ruleSet) refresh(now time.Time) {
	rs.mu.RLock()
	checkFiles := !now.Before(rs.nextCheck)
	old := rs.snapshot
	rs.mu.RUnlock()

	changed := old == nil || (!old.nextExpiry.IsZero() && !now.Before(old.nextExpiry))

	if checkFiles {
		for _, f := range rs.files {
			if f.check() {
				changed = true
			}
		}
	}

	c := old
	if changed {
		var all []*rule
		for _, f := range rs.files {
			all = append(all, f.rules...)
		}

		c = compile(all, now)
	}

	rs.mu.Lock()
	rs.snapshot = c
	if checkFiles {
		rs.nextCheck = now.Add(rs.reload)
	}
	rs.mu.Unlock()
}

// check stats the file and reparses it when its mtime or size changed. It
// reports whether the file's rules changed. A missing file has no rules. A
// file that cannot be read keeps its previous rules.
func (f *ruleFile) check() bool {
	info, err := os.Stat(f.path)

	switch {
	case errors.Is(err, fs.ErrNotExist):
		if !f.exists {
			return false
		}

		*f = ruleFile{path: f.path, parses: f.parses}

		return true
	case err != nil:
		logError(f.path, "cannot stat rule file, keeping its previous rules: "+err.Error())

		return false
	}

	if f.exists && info.ModTime().Equal(f.modTime) && info.Size() == f.size {
		return false
	}

	data, err := os.ReadFile(f.path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return false
		}

		logError(f.path, "cannot read rule file, keeping its previous rules: "+err.Error())

		return false
	}

	f.parses++
	// Separate assignments: Yaegi drops values in a tuple assignment to
	// struct fields.
	f.exists = true
	f.modTime = info.ModTime()
	f.size = info.Size()

	res := parseRules(data)
	f.rules = res.rules

	for _, w := range res.warnings {
		logWarn(f.path, "skipped rule: "+w)
	}

	if len(res.ignored) > 0 {
		logInfo(f.path, fmt.Sprintf("loaded %d rules, ignored %s", len(res.rules), ignoredSummary(res.ignored)))
	}

	return true
}

// ignoredSummary writes the ignored counts in a fixed order, such as
// "action signal: 2, kind email-domain: 3".
func ignoredSummary(ignored map[string]int) string {
	keys := make([]string, 0, len(ignored))
	for k := range ignored {
		keys = append(keys, k)
	}

	sort.Strings(keys)

	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, fmt.Sprintf("%s: %d", k, ignored[k]))
	}

	return strings.Join(parts, ", ")
}
