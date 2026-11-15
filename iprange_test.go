package bantasy

import (
	"net/netip"
	"testing"
)

func ipRules(t *testing.T, matches ...string) []*rule {
	t.Helper()

	rules := make([]*rule, 0, len(matches))

	for _, m := range matches {
		p, err := parsePrefix(m)
		if err != nil {
			t.Fatalf("parsePrefix(%q): %v", m, err)
		}

		rules = append(rules, &rule{Kind: kindIP, Match: m, prefix: p})
	}

	return rules
}

// lookupMatch returns the match of the rule that holds addr, or "".
func lookupMatch(idx *ipIndex, addr string) string {
	r := idx.lookup(netip.MustParseAddr(addr))
	if r == nil {
		return ""
	}

	return r.Match
}

func TestIPIndexLookup(t *testing.T) {
	idx := newIPIndex(ipRules(t,
		"203.0.113.7",
		"198.51.100.0/24",
		"10.20.0.0/16",
		"2001:db8::1",
		"2001:db8:1::/64",
		"2400:cb00::/32",
	))

	tests := []struct {
		addr string
		want string // match of the rule, or "" for no match
	}{
		{"203.0.113.7", "203.0.113.7"},
		{"203.0.113.6", ""},
		{"203.0.113.8", ""},
		{"198.51.100.0", "198.51.100.0/24"},
		{"198.51.100.255", "198.51.100.0/24"},
		{"198.51.101.0", ""},
		{"198.51.99.255", ""},
		{"10.20.0.0", "10.20.0.0/16"},
		{"10.20.255.255", "10.20.0.0/16"},
		{"10.21.0.0", ""},
		{"::ffff:198.51.100.9", "198.51.100.0/24"},
		{"2001:db8::1", "2001:db8::1"},
		{"2001:db8::2", ""},
		{"2001:db8:1::", "2001:db8:1::/64"},
		{"2001:db8:1::ffff:ffff:ffff:ffff", "2001:db8:1::/64"},
		{"2001:db8:1:1::", ""},
		{"2400:cb00::", "2400:cb00::/32"},
		{"2400:cb00:ffff:ffff:ffff:ffff:ffff:ffff", "2400:cb00::/32"},
		{"2400:cb01::", ""},
		{"0.0.0.0", ""},
		{"255.255.255.255", ""},
		{"::", ""},
		{"ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", ""},
	}

	for _, tt := range tests {
		if got := lookupMatch(&idx, tt.addr); got != tt.want {
			t.Errorf("lookup(%s) = %q, want %q", tt.addr, got, tt.want)
		}
	}
}

func TestIPIndexAllIPv4(t *testing.T) {
	idx := newIPIndex(ipRules(t, "0.0.0.0/0"))

	for _, a := range []string{"0.0.0.0", "8.8.8.8", "255.255.255.255", "::ffff:1.2.3.4"} {
		if idx.lookup(netip.MustParseAddr(a)) == nil {
			t.Errorf("0.0.0.0/0 does not hold %s", a)
		}
	}

	for _, a := range []string{"::1", "2001:db8::1", "::fffe:ffff:ffff"} {
		if idx.lookup(netip.MustParseAddr(a)) != nil {
			t.Errorf("0.0.0.0/0 holds %s", a)
		}
	}
}

func TestIPIndexOverlap(t *testing.T) {
	// A wide range that starts first and a narrow range nested in it, plus a
	// later range: the lookup must still find the wide range past the narrow
	// one.
	idx := newIPIndex(ipRules(t, "10.0.0.0/8", "10.1.0.0/16", "10.200.0.0/16"))

	tests := []struct {
		addr string
		want string
	}{
		{"10.1.2.3", "10.1.0.0/16"},
		{"10.2.0.0", "10.0.0.0/8"},
		{"10.199.0.1", "10.0.0.0/8"},
		{"10.200.0.1", "10.200.0.0/16"},
		{"10.255.255.255", "10.0.0.0/8"},
		{"11.0.0.0", ""},
		{"9.255.255.255", ""},
	}

	for _, tt := range tests {
		if got := lookupMatch(&idx, tt.addr); got != tt.want {
			t.Errorf("lookup(%s) = %q, want %q", tt.addr, got, tt.want)
		}
	}
}

func TestIPIndexInvalidAddr(t *testing.T) {
	idx := newIPIndex(ipRules(t, "0.0.0.0/0"))
	if idx.lookup(netip.Addr{}) != nil {
		t.Error("an invalid address matched")
	}
}
