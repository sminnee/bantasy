package bantasy

import (
	"bytes"
	"fmt"
	"net/netip"
	"sort"
	"strings"
)

// ipRange is one rule's prefix as an inclusive range of 16-byte addresses.
// IPv4 prefixes are stored in their IPv4-mapped IPv6 form.
type ipRange struct {
	start [16]byte
	end   [16]byte
	rule  *rule
}

// ipIndex finds the rule whose prefix holds an address. Ranges are sorted by
// start and not merged, so each keeps its own rule. maxEnd[i] is the largest
// end of ranges[0..i]; it lets a lookup stop as soon as no earlier range can
// reach the address.
type ipIndex struct {
	ranges []ipRange
	maxEnd [][16]byte
}

// parsePrefix reads an IP rule's match: an address or a CIDR prefix.
// A bare address is a /32 or /128.
func parsePrefix(s string) (netip.Prefix, error) {
	if strings.Contains(s, "/") {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			return netip.Prefix{}, fmt.Errorf("bad CIDR %q: %w", s, err)
		}

		return p.Masked(), nil
	}

	a, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Prefix{}, fmt.Errorf("bad IP address %q: %w", s, err)
	}

	a = a.WithZone("")

	return netip.PrefixFrom(a, a.BitLen()), nil
}

// prefixRange returns the first and last 16-byte address of p.
func prefixRange(p netip.Prefix) ([16]byte, [16]byte) {
	start := p.Addr().As16()
	bits := p.Bits()

	if p.Addr().Is4() {
		bits += 96
	}

	end := start

	for i := bits; i < 128; i++ {
		end[i/8] |= 1 << (7 - uint(i%8))
	}

	return start, end
}

func newIPIndex(rules []*rule) ipIndex {
	ranges := make([]ipRange, 0, len(rules))

	for _, r := range rules {
		start, end := prefixRange(r.prefix)
		ranges = append(ranges, ipRange{start: start, end: end, rule: r})
	}

	sort.Slice(ranges, func(i, j int) bool {
		return bytes.Compare(ranges[i].start[:], ranges[j].start[:]) < 0
	})

	maxEnd := make([][16]byte, len(ranges))

	for i := range ranges {
		maxEnd[i] = ranges[i].end
		if i > 0 && bytes.Compare(maxEnd[i-1][:], maxEnd[i][:]) > 0 {
			maxEnd[i] = maxEnd[i-1]
		}
	}

	return ipIndex{ranges: ranges, maxEnd: maxEnd}
}

// lookup returns a rule whose range holds addr, or nil. When ranges overlap,
// it returns the one with the latest start.
func (x *ipIndex) lookup(addr netip.Addr) *rule {
	if !addr.IsValid() || len(x.ranges) == 0 {
		return nil
	}

	a := addr.As16()

	// i is the first range that starts after a.
	i := sort.Search(len(x.ranges), func(i int) bool {
		return bytes.Compare(x.ranges[i].start[:], a[:]) > 0
	})

	for j := i - 1; j >= 0; j-- {
		if bytes.Compare(x.maxEnd[j][:], a[:]) < 0 {
			return nil
		}

		if bytes.Compare(x.ranges[j].end[:], a[:]) >= 0 {
			return x.ranges[j].rule
		}
	}

	return nil
}
