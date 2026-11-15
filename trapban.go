package bantasy

import (
	"net/netip"
	"sync"
	"time"
)

// trapBan is one entry of the trap-ban table.
type trapBan struct {
	expires time.Time
	// rule is the trap rule that caused the ban.
	rule *rule
}

// trapSweepInterval is the shortest time between two sweeps of expired
// entries from a full table.
const trapSweepInterval = time.Minute

// trapTable holds trap bans in memory. It holds at most max entries.
type trapTable struct {
	mu        sync.RWMutex
	max       int
	bans      map[[16]byte]trapBan
	nextSweep time.Time
}

func newTrapTable(maxEntries int) *trapTable {
	return &trapTable{max: maxEntries, bans: map[[16]byte]trapBan{}}
}

// add bans ip until expires. An existing ban for ip is only extended, never
// shortened. When the table is full, add drops expired entries, at most once
// per trapSweepInterval, and then any one entry if it is still full. A sweep
// scans the whole table under the write lock, so an attacker who keeps the
// table full must not cause one per request.
func (t *trapTable) add(ip netip.Addr, ban trapBan, now time.Time) {
	key := ip.As16()

	t.mu.Lock()
	defer t.mu.Unlock()

	if old, ok := t.bans[key]; ok {
		if ban.expires.After(old.expires) {
			t.bans[key] = ban
		}

		return
	}

	if len(t.bans) >= t.max && !now.Before(t.nextSweep) {
		t.dropExpired(now)
		t.nextSweep = now.Add(trapSweepInterval)
	}

	if len(t.bans) >= t.max {
		t.dropAny()
	}

	t.bans[key] = ban
}

// lookup returns the live ban for ip, if any.
func (t *trapTable) lookup(ip netip.Addr, now time.Time) (trapBan, bool) {
	if !ip.IsValid() {
		return trapBan{}, false
	}

	t.mu.RLock()
	ban, ok := t.bans[ip.As16()]
	t.mu.RUnlock()

	if !ok || !now.Before(ban.expires) {
		return trapBan{}, false
	}

	return ban, true
}

func (t *trapTable) dropExpired(now time.Time) {
	for k, b := range t.bans {
		if !now.Before(b.expires) {
			delete(t.bans, k)
		}
	}
}

// dropAny drops one entry. Map order makes the choice arbitrary.
func (t *trapTable) dropAny() {
	for k := range t.bans {
		delete(t.bans, k)

		return
	}
}
