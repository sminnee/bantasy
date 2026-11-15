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
	// lift is set when a pardon rule lifts the client's trap ban, lifted.
	// The caller removes the ban; action and rule are then the outcome as
	// if there was no ban.
	lift   *rule
	lifted trapBan
}

// decide applies the evaluation order: allow rules of every kind, then ip
// rules, then the trap-ban table, where a pardon can lift the ban, then
// path, user-agent and referrer rules. It has no side effects: the caller sets a trap ban on ban-ip, and removes
// one on lift.
func decide(c *compiled, traps *trapTable, req request, now time.Time) decision {
	r := c.match(req)

	if r != nil && (r.Action == actionAllow || r.Kind == kindIP) {
		return decision{action: r.Action, rule: r}
	}

	d := decision{}

	if ban, ok := traps.lookup(req.ip, now); ok {
		p := c.pardoned(req.ip, ban.set, now)
		if p == nil {
			return decision{action: actionTrapBan, rule: ban.rule}
		}

		d.lift = p
		d.lifted = ban
	}

	if r != nil {
		d.action = r.Action
		d.rule = r
	}

	return d
}
