# bantasy glossary

**Rule**: one JSON object on one line of a rule file. It has a kind, a match and an action.
_Avoid_: entry, pattern (use "match" for the pattern field).

**Rule file**: a JSONL file of rules. Any tool can add a rule by appending a line. Several tools share one rule file.
_Avoid_: ban list, config file.

**Rule set**: the live rules that bantasy compiled from one list of rule files. All Middlewares with the same files, `reloadSeconds` and `trapBanMax` share one rule set and one trap-ban table.
_Avoid_: ruleset (one word); snapshot, which names the compiled form inside a rule set.

**Kind**: what a rule matches: `ip`, `path`, `user-agent` or `referrer`.
_Avoid_: type.

**Action**: what happens when a rule matches: `block`, `allow`, `ban-ip` or `signal`. The default is `block`. A third-party action has a source prefix, such as `smartypants:block-signup`; bantasy ignores it.

**Ban**: a rule with action `block` and a kind of `ip`, usually with an `expires`.
_Avoid_: blacklist, denylist entry.

**Allow rule**: a rule with action `allow`. A match passes the request, even when a ban, a trap ban or another rule also matches.
_Avoid_: whitelist.

**Trap rule**: a rule with action `ban-ip`. A match blocks the request and gives the client IP a trap ban.
_Avoid_: fail2ban rule, honeypot.

**Trap ban**: an entry in the in-memory trap-ban table. It blocks every request from one client IP until it expires. Each Traefik pod has its own table, and a restart clears it.
_Avoid_: temporary ban, jail.

**Signal**: a rule with action `signal`. It is evidence for other tools. bantasy ignores it.
_Avoid_: report, hint.

**Foreign kind**: a kind that bantasy does not know, such as `email-domain`. bantasy ignores rules of a foreign kind, so other tools can keep their records in the same rule files.

**Writer**: a tool or person that adds, changes or removes rules in a rule file. The plugin reads rule files and is never a writer. The CLI, `cmd/bantasy`, is a writer.

**Target**: one rule file that the CLI reads or writes: a local file, or one key of one ConfigMap.
_Avoid_: destination, store.

**Cause**: the `id` of the rule or signal that led to a rule or a trap ban. bantasy logs it and does not check it.
