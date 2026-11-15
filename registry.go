package bantasy

import (
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"
)

// shared is the state that Middleware instances with the same config share:
// one rule set and one trap-ban table. A trap on one route bans the IP on
// all of them, and N routes stat the files once per interval, not N times.
type shared struct {
	rules *ruleSet
	traps *trapTable
}

// registry holds one shared state per set of files, reloadSeconds and
// trapBanMax. Entries are never removed: Traefik makes a Middleware again on
// each config change, and the number of distinct configs is small.
var registry = struct {
	mu      sync.Mutex
	entries map[string]*shared
}{entries: map[string]*shared{}}

// sharedState returns the shared state for a config, and makes it on first
// use, with one info line per rule file. defaulted marks files that came
// from the default, not the config. The first caller's now is the rule
// set's clock.
func sharedState(files []string, defaulted bool, reload time.Duration, trapBanMax int, now func() time.Time) *shared {
	sorted := append([]string(nil), files...)
	sort.Strings(sorted)
	key := fmt.Sprintf("%s\x00%s\x00%d", strings.Join(sorted, "\x00"), reload, trapBanMax)

	registry.mu.Lock()
	defer registry.mu.Unlock()

	s, ok := registry.entries[key]
	if !ok {
		msg := "reading rule file"
		if defaulted {
			msg += " (default)"
		}

		for _, f := range files {
			logInfo(f, msg)
		}

		s = &shared{rules: newRuleSet(files, reload, now), traps: newTrapTable(trapBanMax)}
		registry.entries[key] = s
	}

	return s
}
