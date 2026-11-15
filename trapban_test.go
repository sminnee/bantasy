package bantasy

import (
	"net/netip"
	"testing"
	"time"
)

func TestTrapTableExpiry(t *testing.T) {
	tt := newTrapTable(10)
	ip := netip.MustParseAddr("192.0.2.1")
	trap := &rule{ID: "trap"}

	tt.add(ip, trapBan{expires: t0.Add(time.Minute), rule: trap}, t0)

	ban, ok := tt.lookup(ip, t0.Add(59*time.Second))
	if !ok || ban.rule != trap {
		t.Fatalf("lookup before expiry = %v, %v", ban, ok)
	}

	if _, ok := tt.lookup(ip, t0.Add(time.Minute)); ok {
		t.Error("ban still live at its expiry")
	}

	if _, ok := tt.lookup(netip.MustParseAddr("192.0.2.2"), t0); ok {
		t.Error("other IP is banned")
	}
}

func TestTrapTableExtendsOnly(t *testing.T) {
	tt := newTrapTable(10)
	ip := netip.MustParseAddr("2001:db8::1")

	tt.add(ip, trapBan{expires: t0.Add(time.Hour)}, t0)
	tt.add(ip, trapBan{expires: t0.Add(time.Minute)}, t0)

	if _, ok := tt.lookup(ip, t0.Add(30*time.Minute)); !ok {
		t.Error("a shorter ban shortened the existing ban")
	}
}

func TestTrapTableBound(t *testing.T) {
	addr := netip.MustParseAddr

	tt := newTrapTable(3)
	tt.add(addr("192.0.2.1"), trapBan{expires: t0.Add(1 * time.Minute)}, t0)
	tt.add(addr("192.0.2.2"), trapBan{expires: t0.Add(3 * time.Minute)}, t0)
	tt.add(addr("192.0.2.3"), trapBan{expires: t0.Add(2 * time.Minute)}, t0)

	// Full, nothing expired: one entry goes, and the new one is in.
	tt.add(addr("192.0.2.4"), trapBan{expires: t0.Add(10 * time.Minute)}, t0)

	if len(tt.bans) != 3 {
		t.Fatalf("table has %d entries, want 3", len(tt.bans))
	}

	if _, ok := tt.lookup(addr("192.0.2.4"), t0); !ok {
		t.Error("new entry is missing")
	}

	// Full, all old entries expired: the sweep drops them all, so no live
	// entry goes.
	now := t0.Add(5 * time.Minute)
	tt.add(addr("192.0.2.5"), trapBan{expires: now.Add(time.Minute)}, now)

	if len(tt.bans) != 2 {
		t.Errorf("table has %d entries, want 2 after expired entries dropped", len(tt.bans))
	}

	for _, a := range []string{"192.0.2.4", "192.0.2.5"} {
		if _, ok := tt.lookup(addr(a), now); !ok {
			t.Errorf("%s was dropped", a)
		}
	}
}
