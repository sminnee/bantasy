package bantasy

import "time"

// actionTrapBan is the decision for a request blocked by the trap-ban
// table. It is not a rule action.
const actionTrapBan = "trap-ban"

// decision is the outcome for one request. action is "" (pass, no rule
// matched), allow, block, ban-ip or trap-ban. rule is the deciding rule; for
// trap-ban it is the trap rule that caused the ban.
type decision struct {
	action string
	rule   *rule
}

// decide applies the evaluation order: allow rules of every kind, then ip
// rules, then the trap-ban table, then path, user-agent and referrer rules.
// It has no side effects: the caller sets a trap ban on ban-ip.
func decide(c *compiled, traps *trapTable, req request, now time.Time) decision {
	r := c.match(req)

	if r != nil && (r.Action == actionAllow || r.Kind == kindIP) {
		return decision{action: r.Action, rule: r}
	}

	if ban, ok := traps.lookup(req.ip, now); ok {
		return decision{action: actionTrapBan, rule: ban.rule}
	}

	if r == nil {
		return decision{}
	}

	return decision{action: r.Action, rule: r}
}
