package bantasy

import (
	"net/netip"
	"testing"
	"time"
)

func TestDecideOrder(t *testing.T) {
	c := mustCompile(t, `{"id":"ipban","kind":"ip","match":"192.0.2.1"}
{"id":"php","kind":"path","match":"\\.php$"}
{"id":"trap","kind":"path","match":"^/trap","action":"ban-ip"}
{"id":"monitor","kind":"user-agent","match":"UptimeRobot","action":"allow"}
{"id":"pardon-one","kind":"ip","match":"192.0.2.3","action":"pardon","added":"2026-11-15T03:00:00Z"}
{"id":"pardon-net","kind":"ip","match":"198.51.100.0/24","action":"pardon","added":"2026-11-15T03:00:00Z"}
{"id":"ipban2","kind":"ip","match":"192.0.2.5"}
{"id":"pardon-ip","kind":"ip","match":"192.0.2.5","action":"pardon","added":"2026-11-15T03:00:00Z"}
{"id":"pardon-future","kind":"ip","match":"192.0.2.6","action":"pardon","added":"2026-11-15T03:05:01Z"}
{"id":"pardon-old","kind":"ip","match":"192.0.2.4","action":"pardon","added":"2026-11-15T03:00:00Z","expires":"2026-11-15T03:00:00Z"}
`, t0)

	trapRule := &rule{ID: "trap-rule"}
	traps := newTrapTable(10)

	// Bans set one second before the pardons' added time, except
	// 198.51.100.8, set at it.
	before := t0.Add(-time.Second)

	for _, ip := range []string{"192.0.2.1", "192.0.2.2", "192.0.2.3", "192.0.2.4", "192.0.2.5", "192.0.2.6", "198.51.100.7"} {
		traps.add(netip.MustParseAddr(ip), trapBan{expires: t0.Add(time.Hour), set: before, rule: trapRule}, t0)
	}

	traps.add(netip.MustParseAddr("198.51.100.8"), trapBan{expires: t0.Add(time.Hour), set: t0, rule: trapRule}, t0)

	tests := []struct {
		name, ip, uri, ua string
		want              string // action, rule id and lift id
	}{
		{"pardon lifts an older ban", "192.0.2.3", "/", "", "  pardon-one"},
		{"lifted ban, then path rule", "192.0.2.3", "/a.php", "", "block php pardon-one"},
		{"CIDR pardon", "198.51.100.7", "/", "", "  pardon-net"},
		{"ban set at added is not lifted", "198.51.100.8", "/", "", "trap-ban trap-rule "},
		{"pardon with added past the skew", "192.0.2.6", "/", "", "trap-ban trap-rule "},
		{"expired pardon", "192.0.2.4", "/", "", "trap-ban trap-rule "},
		{"ip rule beats pardon", "192.0.2.5", "/", "", "block ipban2 "},
		{"allow beats pardon", "192.0.2.3", "/", "UptimeRobot", "allow monitor "},
		{"no match", "192.0.2.9", "/", "", "  "},
		{"path rule", "192.0.2.9", "/a.php", "", "block php "},
		{"trap rule", "192.0.2.9", "/trap", "", "ban-ip trap "},
		{"allow beats trap ban", "192.0.2.2", "/", "UptimeRobot", "allow monitor "},
		{"allow beats ip rule", "192.0.2.1", "/", "UptimeRobot", "allow monitor "},
		{"ip rule beats trap ban", "192.0.2.1", "/", "", "block ipban "},
		{"trap ban beats path rule", "192.0.2.2", "/a.php", "", "trap-ban trap-rule "},
		{"trap ban beats trap rule", "192.0.2.2", "/trap", "", "trap-ban trap-rule "},
		{"trap ban on clean path", "192.0.2.2", "/", "", "trap-ban trap-rule "},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := decide(c, traps, newRequest(netip.MustParseAddr(tt.ip), tt.uri, tt.ua, ""), t0)

			id, lift := "", ""
			if d.rule != nil {
				id = d.rule.ID
			}

			if d.lift != nil {
				lift = d.lift.ID
			}

			if got := d.action + " " + id + " " + lift; got != tt.want {
				t.Errorf("got %q, want %q", got, tt.want)
			}
		})
	}
}
