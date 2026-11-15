package bantasy

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"strings"
	"time"
)

// Rule kinds that bantasy matches. Other kinds are foreign kinds: bantasy
// ignores them.
const (
	kindIP        = "ip"
	kindPath      = "path"
	kindUserAgent = "user-agent"
	kindReferrer  = "referrer"
)

// Rule actions that bantasy applies. bantasy ignores every other action,
// such as "signal".
const (
	actionBlock  = "block"
	actionAllow  = "allow"
	actionBanIP  = "ban-ip"
	actionPardon = "pardon"
)

// pardonSkew is how far a pardon's added time can be after the clock. A
// pardon with a later added lifts nothing: else a wrong added (a typo, a bad
// clock) would lift every trap ban on its range until that time.
const pardonSkew = 5 * time.Minute

// maxBanSeconds (100 years) keeps a ban time well inside time.Duration.
const maxBanSeconds = 100 * 365 * 24 * 3600

// rule is one line of a rule file. Unknown JSON fields are ignored, so newer
// writers do not break older readers.
type rule struct {
	ID         string     `json:"id,omitempty"`
	Kind       string     `json:"kind"`
	Match      string     `json:"match"`
	Action     string     `json:"action,omitempty"`
	BanSeconds int        `json:"banSeconds,omitempty"`
	Reason     string     `json:"reason,omitempty"`
	Source     string     `json:"source,omitempty"`
	Cause      string     `json:"cause,omitempty"`
	Added      *time.Time `json:"added,omitempty"`
	Expires    *time.Time `json:"expires,omitempty"`

	prefix netip.Prefix   // kind ip
	re     *regexp.Regexp // kind path
	lower  string         // kinds user-agent and referrer
}

// parseResult is the outcome of parsing one rule file.
type parseResult struct {
	rules []*rule
	// ignored counts the rules bantasy does not use, keyed by
	// "kind <kind>" or "action signal".
	ignored map[string]int
	// warnings name each skipped bad line, with its line number.
	warnings []string
}

// parseRules reads JSONL rule data. Each bad line is skipped with a warning;
// the other lines still load. Blank lines are ignored.
//
// A last line with no trailing newline may be a write in progress. It loads
// when it parses, and is skipped with no warning when it does not: a
// half-written JSON object never parses, and some writers (such as a join
// on "\n") never add the final newline.
func parseRules(data []byte) parseResult {
	res := parseResult{ignored: map[string]int{}}
	lineNo := 0

	for len(data) > 0 {
		var line []byte

		partial := false

		nl := bytes.IndexByte(data, '\n')
		if nl < 0 {
			line = bytes.TrimSpace(data)
			data = nil
			partial = true
		} else {
			line = bytes.TrimSpace(data[:nl])
			data = data[nl+1:]
		}

		lineNo++

		if len(line) == 0 {
			continue
		}

		r, ignored, err := parseRule(line)

		switch {
		case err != nil && partial:
		case err != nil:
			res.warnings = append(res.warnings, fmt.Sprintf("line %d: %v", lineNo, err))
		case ignored != "":
			res.ignored[ignored]++
		default:
			res.rules = append(res.rules, r)
		}
	}

	return res
}

// parseRule decodes and validates one line. It returns either a rule, the
// reason the rule is ignored, or an error.
func parseRule(line []byte) (*rule, string, error) {
	r := &rule{}
	if err := json.Unmarshal(line, r); err != nil {
		return nil, "", fmt.Errorf("bad JSON: %w", err)
	}

	if r.Kind == "" {
		return nil, "", errors.New("no kind")
	}

	if !knownKind(r.Kind) {
		return nil, "kind " + r.Kind, nil
	}

	if ignored, err := normalizeAction(r); ignored != "" || err != nil {
		return nil, ignored, err
	}

	if r.Match == "" {
		return nil, "", errors.New("empty match")
	}

	if r.BanSeconds < 0 || r.BanSeconds > maxBanSeconds {
		return nil, "", fmt.Errorf("banSeconds must be 0 to %d", maxBanSeconds)
	}

	if err := r.compileMatch(); err != nil {
		return nil, "", err
	}

	return r, "", nil
}

// normalizeAction sets the default action, validates it for the rule's
// kind, and makes ban-ip on an ip rule a block. It returns the reason the
// rule is ignored, or an error.
func normalizeAction(r *rule) (string, error) {
	if r.Action == "" {
		r.Action = actionBlock
	}

	// Signals and actions that bantasy does not know (such as a third
	// party's "smartypants:block-signup") are records for other tools.
	switch r.Action {
	case actionBlock, actionAllow:
	case actionBanIP:
		// An ip rule already blocks every request from its range, so a
		// trap ban would add nothing.
		if r.Kind == kindIP {
			r.Action = actionBlock
		}
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

	return "", nil
}

func knownKind(kind string) bool {
	switch kind {
	case kindIP, kindPath, kindUserAgent, kindReferrer:
		return true
	}

	return false
}

// compileMatch prepares the match for its kind.
func (r *rule) compileMatch() error {
	switch r.Kind {
	case kindIP:
		p, err := parsePrefix(r.Match)
		if err != nil {
			return err
		}

		r.prefix = p
	case kindPath:
		re, err := regexp.Compile(r.Match)
		if err != nil {
			return fmt.Errorf("bad regexp: %w", err)
		}

		r.re = re
	default:
		r.lower = strings.ToLower(r.Match)
	}

	return nil
}

// ruleList holds the rules of one side, allow or not, by kind.
type ruleList struct {
	ipRules  []*rule
	ip       ipIndex
	path     []*rule
	ua       []*rule
	referrer []*rule
}

func (l *ruleList) add(r *rule) {
	switch r.Kind {
	case kindIP:
		l.ipRules = append(l.ipRules, r)
	case kindPath:
		l.path = append(l.path, r)
	case kindUserAgent:
		l.ua = append(l.ua, r)
	case kindReferrer:
		l.referrer = append(l.referrer, r)
	}
}

// compiled is a snapshot of the live rules, ready to match.
type compiled struct {
	allow ruleList
	block ruleList
	// pardons apply only to trap bans, so they are in neither allow nor block.
	pardons []*rule
	// nextExpiry is the earliest future expires of any rule, or zero. When
	// the clock passes it, the rule set recompiles.
	nextExpiry time.Time
}

// compile drops the rules that have expired at now and indexes the rest.
func compile(rules []*rule, now time.Time) *compiled {
	c := &compiled{}

	for _, r := range rules {
		if r.Expires != nil {
			if !now.Before(*r.Expires) {
				continue
			}

			if c.nextExpiry.IsZero() || r.Expires.Before(c.nextExpiry) {
				c.nextExpiry = *r.Expires
			}
		}

		switch r.Action {
		case actionPardon:
			c.pardons = append(c.pardons, r)
		case actionAllow:
			c.allow.add(r)
		default:
			c.block.add(r)
		}
	}

	c.allow.ip = newIPIndex(c.allow.ipRules)
	c.block.ip = newIPIndex(c.block.ipRules)

	return c
}

// pardoned returns the pardon rule that lifts a trap ban on ip set at set,
// or nil. A pardon lifts only bans set before its added time, so a later
// trap bans the IP again. A pardon with added more than pardonSkew after now
// lifts nothing. Pardons are few, and this runs only on a trap-ban
// hit, so a linear scan is enough.
func (c *compiled) pardoned(ip netip.Addr, set, now time.Time) *rule {
	latest := now.Add(pardonSkew)

	for _, r := range c.pardons {
		if r.prefix.Contains(ip) && set.Before(*r.Added) && !r.Added.After(latest) {
			return r
		}
	}

	return nil
}

// request is the part of an HTTP request that rules match on. ua and
// referrer are lower-cased.
type request struct {
	ip       netip.Addr
	uri      string
	ua       string
	referrer string
}

func newRequest(ip netip.Addr, uri, ua, referrer string) request {
	return request{ip: ip, uri: uri, ua: strings.ToLower(ua), referrer: strings.ToLower(referrer)}
}

// match returns the rule that decides req, or nil. An allow rule of any kind
// wins first; then ip, path, user-agent and referrer block rules, in that
// order.
func (c *compiled) match(req request) *rule {
	if r := c.allow.match(req); r != nil {
		return r
	}

	return c.block.match(req)
}

func (l *ruleList) match(req request) *rule {
	if r := l.ip.lookup(req.ip); r != nil {
		return r
	}

	for _, r := range l.path {
		if r.re.MatchString(req.uri) {
			return r
		}
	}

	if req.ua != "" {
		for _, r := range l.ua {
			if strings.Contains(req.ua, r.lower) {
				return r
			}
		}
	}

	if req.referrer != "" {
		for _, r := range l.referrer {
			if strings.Contains(req.referrer, r.lower) {
				return r
			}
		}
	}

	return nil
}
