package main

import (
	"encoding/json"
	"net/netip"
	"strings"
	"testing"
)

func TestRangeCIDRs(t *testing.T) {
	cases := []struct {
		start, end, want string
	}{
		{"158.173.167.0", "158.173.167.255", "158.173.167.0/24"},
		{"198.51.100.5", "198.51.100.5", "198.51.100.5/32"},
		{"10.0.0.1", "10.0.0.10", "10.0.0.1/32 10.0.0.2/31 10.0.0.4/30 10.0.0.8/31 10.0.0.10/32"},
		{"31.0.0.0", "31.2.255.255", "31.0.0.0/15 31.2.0.0/16"},
		{"2001:4860::", "2001:4860:ffff:ffff:ffff:ffff:ffff:ffff", "2001:4860::/32"},
		{"0.0.0.0", "255.255.255.255", "0.0.0.0/0"},
		{"255.255.255.254", "255.255.255.255", "255.255.255.254/31"},
		{"10.0.0.2", "10.0.0.1", ""},
		{"10.0.0.1", "::1", ""},
		{"fe80::1%eth0", "fe80::ff%eth0", ""},
	}

	for _, c := range cases {
		var got []string
		for _, p := range rangeCIDRs(netip.MustParseAddr(c.start), netip.MustParseAddr(c.end)) {
			got = append(got, p.String())
		}

		if s := strings.Join(got, " "); s != c.want {
			t.Errorf("%s-%s = %q, want %q", c.start, c.end, s, c.want)
		}
	}
}

func TestVcardField(t *testing.T) {
	cases := []struct{ raw, want string }{
		{`["vcard",[["version",{},"text","4.0"],["fn",{},"text","Example Ltd"]]]`, "Example Ltd"},
		{`["vcard",[["version",{},"text","4.0"]]]`, ""},
		{`["vcard",[["fn",{},"text",["a","b"]],["fn",{}]]]`, ""},
		{`["vcard"]`, ""},
		{`"vcard"`, ""},
		{`null`, ""},
		{``, ""},
	}

	for _, c := range cases {
		if got := vcardField(json.RawMessage(c.raw), "fn"); got != c.want {
			t.Errorf("%s: %q, want %q", c.raw, got, c.want)
		}
	}
}
