package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

// Kinds that add accepts. email-domain is a foreign kind: bantasy ignores it,
// and askastro's sign-up check reads it.
const (
	kindIP          = "ip"
	kindPath        = "path"
	kindUserAgent   = "user-agent"
	kindReferrer    = "referrer"
	kindEmailDomain = "email-domain"
)

const (
	actionBlock  = "block"
	actionAllow  = "allow"
	actionBanIP  = "ban-ip"
	actionSignal = "signal"
	actionPardon = "pardon"
)

const (
	// A fragment is a substring test, so a short one matches most clients.
	minFragment = 4
	maxFragment = 200
	maxDomain   = 253
	// maxBanSeconds is the reader's limit: 100 years.
	maxBanSeconds = 100 * 365 * 24 * 3600
	maxTTL        = maxBanSeconds * time.Second
)

// A prefix wider than these blocks too many clients at once.
const (
	minBits4 = 16
	minBits6 = 32
)

// specialPrefixes are the ranges of the IANA IPv4 and IPv6 special-purpose
// address registries that are not globally reachable, plus multicast.
var specialPrefixes = mustPrefixes(
	"0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16",
	"172.16.0.0/12", "192.0.0.0/24", "192.0.2.0/24", "192.88.99.0/24", "192.168.0.0/16",
	"198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "224.0.0.0/4", "240.0.0.0/4",
	"::/128", "::1/128", "::ffff:0:0/96", "64:ff9b:1::/48", "100::/64", "2001::/23",
	"2001:db8::/32", "2002::/16", "3fff::/20", "5f00::/16", "fc00::/7", "fe80::/10", "ff00::/8",
)

var (
	ttlPattern   = regexp.MustCompile(`^([1-9][0-9]*)([mhd])$`)
	labelPattern = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)
)

func mustPrefixes(texts ...string) []netip.Prefix {
	out := make([]netip.Prefix, 0, len(texts))
	for _, t := range texts {
		out = append(out, netip.MustParsePrefix(t))
	}

	return out
}

// parseIPMatch parses an ip match, an address or a CIDR, as a masked
// prefix. It refuses an address with a zone.
func parseIPMatch(text string) (netip.Prefix, error) {
	text = strings.TrimSpace(text)

	if strings.Contains(text, "/") {
		p, err := netip.ParsePrefix(text)
		if err != nil {
			return netip.Prefix{}, fmt.Errorf("not an IP address or CIDR: %q", text)
		}

		return p.Masked(), nil
	}

	a, err := netip.ParseAddr(text)
	if err != nil || a.Zone() != "" {
		return netip.Prefix{}, fmt.Errorf("not an IP address or CIDR: %q", text)
	}

	return netip.PrefixFrom(a, a.BitLen()), nil
}

// normaliseIP returns the masked network of an address or CIDR: a bare
// address for one host. It refuses non-public ranges and wide prefixes.
func normaliseIP(text string) (string, error) {
	p, err := parseIPMatch(text)
	if err != nil {
		return "", err
	}

	for _, s := range specialPrefixes {
		if p.Overlaps(s) {
			return "", fmt.Errorf("%s is not a public range: it overlaps %s", p, s)
		}
	}

	minBits := minBits6
	if p.Addr().Is4() {
		minBits = minBits4
	}

	if p.Bits() < minBits {
		return "", fmt.Errorf("%s is too wide: the prefix must be /%d or longer", p, minBits)
	}

	return ipMatch(p), nil
}

// ipMatch is the match text of p: a bare address for one host.
func ipMatch(p netip.Prefix) string {
	if p.IsSingleIP() {
		return p.Addr().String()
	}

	return p.String()
}

// normaliseFragment trims a user-agent or referrer match and keeps its case.
func normaliseFragment(text string) (string, error) {
	f := strings.TrimSpace(text)

	n := utf8.RuneCountInString(f)
	if n < minFragment || n > maxFragment {
		return "", fmt.Errorf("match must be %d to %d characters: %q", minFragment, maxFragment, f)
	}

	if strings.IndexFunc(f, unicode.IsControl) >= 0 {
		return "", fmt.Errorf("match has a control character: %q", f)
	}

	return f, nil
}

// normaliseDomain returns the lower-case domain with no trailing dot.
func normaliseDomain(text string) (string, error) {
	d := strings.TrimRight(strings.ToLower(strings.TrimSpace(text)), ".")
	labels := strings.Split(d, ".")

	if len(d) > maxDomain || len(labels) < 2 {
		return "", fmt.Errorf("not a domain: %q", text)
	}

	for _, l := range labels {
		if !labelPattern.MatchString(l) {
			return "", fmt.Errorf("not a domain: %q", text)
		}
	}

	return d, nil
}

// checkPath refuses an empty match and a match that is not a Go regexp.
func checkPath(text string) (string, error) {
	if text == "" {
		return "", errors.New("empty path match")
	}

	if _, err := regexp.Compile(text); err != nil {
		return "", fmt.Errorf("bad regexp: %w", err)
	}

	return text, nil
}

// normaliseMatch applies the add check for kind.
func normaliseMatch(kind, text string) (string, error) {
	switch kind {
	case kindIP:
		return normaliseIP(text)
	case kindPath:
		return checkPath(text)
	case kindUserAgent, kindReferrer:
		return normaliseFragment(text)
	case kindEmailDomain:
		return normaliseDomain(text)
	}

	return "", fmt.Errorf("kind %q: use ip, path, user-agent, referrer or email-domain", kind)
}

// parseTTL reads 30m, 24h, 7d or never. never returns 0.
func parseTTL(text string) (time.Duration, error) {
	text = strings.TrimSpace(text)
	if text == "never" {
		return 0, nil
	}

	m := ttlPattern.FindStringSubmatch(text)
	if m == nil {
		return 0, fmt.Errorf("bad TTL %q: use a number and m, h or d (such as 30m, 24h or 7d), or never", text)
	}

	n, err := strconv.ParseInt(m[1], 10, 64)

	unit := time.Minute

	switch m[2] {
	case "h":
		unit = time.Hour
	case "d":
		unit = 24 * time.Hour
	}

	if err != nil || n > int64(maxTTL/unit) {
		return 0, fmt.Errorf("bad TTL %q: longer than 100 years", text)
	}

	return time.Duration(n) * unit, nil
}

// checkAction accepts the bantasy actions and a third-party <source>:<name>.
func checkAction(action string) error {
	switch action {
	case actionBlock, actionAllow, actionBanIP, actionSignal:
		return nil
	case actionPardon:
		return errors.New(`action "pardon": use bantasy unban`)
	}

	src, name, ok := strings.Cut(action, ":")
	if ok && src != "" && name != "" {
		return nil
	}

	return fmt.Errorf("action %q: use block, allow, ban-ip, signal or <source>:<name>", action)
}

// ruleID is <source>:<kind>:<match>. The match is lower-case for the
// case-insensitive kinds, so a change of case keeps the id.
func ruleID(source, kind, match string) string {
	switch kind {
	case kindUserAgent, kindReferrer, kindEmailDomain:
		match = strings.ToLower(match)
	}

	return source + ":" + kind + ":" + match
}

// checkLine is the reader's check of one line. It returns "" for a rule
// bantasy uses, a reason for a rule it ignores, or an error for a bad line.
// It mirrors parseRule in the plugin package; testdata/lines.jsonl keeps
// the two in step.
func checkLine(line []byte) (string, error) {
	var r record
	if err := json.Unmarshal(line, &r); err != nil {
		return "", fmt.Errorf("bad JSON: %w", err)
	}

	if r.Kind == "" {
		return "", errors.New("no kind")
	}

	switch r.Kind {
	case kindIP, kindPath, kindUserAgent, kindReferrer:
	default:
		return "kind " + r.Kind, nil
	}

	switch r.Action {
	case "", actionBlock, actionAllow, actionBanIP:
	case actionPardon:
		if r.Kind != kindIP {
			return "", errors.New("pardon needs kind ip")
		}

		if r.Added == nil {
			return "", errors.New("pardon needs added")
		}
	default:
		return "action " + r.Action, nil
	}

	if r.Match == "" {
		return "", errors.New("empty match")
	}

	if r.BanSeconds < 0 || r.BanSeconds > maxBanSeconds {
		return "", fmt.Errorf("banSeconds must be 0 to %d", maxBanSeconds)
	}

	return "", checkReaderMatch(r.Kind, r.Match)
}

func checkReaderMatch(kind, match string) error {
	switch kind {
	case kindIP:
		if strings.Contains(match, "/") {
			if _, err := netip.ParsePrefix(match); err != nil {
				return fmt.Errorf("bad CIDR %q: %w", match, err)
			}
		} else if _, err := netip.ParseAddr(match); err != nil {
			return fmt.Errorf("bad IP address %q: %w", match, err)
		}
	case kindPath:
		if _, err := regexp.Compile(match); err != nil {
			return fmt.Errorf("bad regexp: %w", err)
		}
	}

	return nil
}
