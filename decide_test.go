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
`, t0)

	trapRule := &rule{ID: "trap-rule"}
	traps := newTrapTable(10)

	for _, ip := range []string{"192.0.2.1", "192.0.2.2"} {
		traps.add(netip.MustParseAddr(ip), trapBan{expires: t0.Add(time.Hour), rule: trapRule}, t0)
	}

	tests := []struct {
		name, ip, uri, ua string
		want              string // action and rule id
	}{
		{"no match", "192.0.2.9", "/", "", " "},
		{"path rule", "192.0.2.9", "/a.php", "", "block php"},
		{"trap rule", "192.0.2.9", "/trap", "", "ban-ip trap"},
		{"allow beats trap ban", "192.0.2.2", "/", "UptimeRobot", "allow monitor"},
		{"allow beats ip rule", "192.0.2.1", "/", "UptimeRobot", "allow monitor"},
		{"ip rule beats trap ban", "192.0.2.1", "/", "", "block ipban"},
		{"trap ban beats path rule", "192.0.2.2", "/a.php", "", "trap-ban trap-rule"},
		{"trap ban beats trap rule", "192.0.2.2", "/trap", "", "trap-ban trap-rule"},
		{"trap ban on clean path", "192.0.2.2", "/", "", "trap-ban trap-rule"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := decide(c, traps, newRequest(netip.MustParseAddr(tt.ip), tt.uri, tt.ua, ""), t0)

			id := ""
			if d.rule != nil {
				id = d.rule.ID
			}

			if got := d.action + " " + id; got != tt.want {
				t.Errorf("got %q, want %q", got, tt.want)
			}
		})
	}
}
