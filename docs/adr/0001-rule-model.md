# ADR 0001: The rule model

Status: accepted, 2026-11-15.

## Context

bantasy blocks bad traffic at the Traefik edge. More than one tool knows about bad actors: patterns kept in a repo, a person with a shell, and application code that sees abuse (such as smartypants refusing a sign-up). These tools need one shared format that they can all write and bantasy can read. Other tools also read the same records later, for example to turn evidence into a ban.

This ADR is the contract for writers and readers of rule files. The terms are in `CONTEXT.md`.

## Decision

### Rule files are JSONL

A rule file holds one JSON rule per line. A writer adds a rule with one append:

```sh
echo '{"kind":"ip","match":"203.0.113.7","reason":"credential stuffing","source":"ops","expires":"2026-11-16T00:00:00Z"}' >> bans.jsonl
```

JSON is used, not YAML, because Traefik plugins can use only the Go standard library, and it has no YAML parser. A Kubernetes ConfigMap replaces its whole value on each write. So a writer to a ConfigMap reads, edits and replaces the value. The append helps local files and scripts most.

### Fields

| Field | Required | Meaning |
|---|---|---|
| `kind` | yes | `ip`, `path`, `user-agent`, `referrer`, or a foreign kind. |
| `match` | yes | The pattern for the kind. It must not be empty. |
| `action` | no | `block` (default), `allow`, `ban-ip`, `signal`, or a third-party action. |
| `banSeconds` | no | For `ban-ip`: the trap-ban time. Absent: the Middleware's `trapBanSeconds`. |
| `id` | no | A writer-chosen string, by convention `<source>:<key>`, such as `smartypants:email-domain:spam.example`. |
| `cause` | no | The `id` of the rule or signal that led to this rule. |
| `reason`, `source` | no | Free text for people and logs. |
| `added`, `expires` | no | RFC 3339 times. An absent or null `expires` means the rule is permanent. |

Matches by kind:

| Kind | Match |
|---|---|
| `ip` | An IPv4 or IPv6 address or CIDR prefix. A bare address is a /32 or /128. |
| `path` | A Go regular expression, matched against the decoded path, plus `?` and the raw query when there is one. |
| `user-agent` | A substring of the `User-Agent` header, case-insensitive. |
| `referrer` | A substring of the `Referer` header, case-insensitive. |

### Kind and action are separate

The kind says what a rule matches. The action says what happens. One combined field (such as `allow-ip`) would need a new value for each pair. With two fields, trap rules and signals use the same kinds as bans.

### Third-party actions

A reader ignores an action it does not know, as it ignores a foreign kind. A tool that needs its own action names it with a colon-delimited prefix of its source, such as `smartypants:block-signup`. The prefix keeps third-party actions apart from each other and from actions that bantasy adds later. Unprefixed action names are reserved for bantasy.

### Evaluation order

1. Allow rules of every kind. A match passes the request.
2. `ip` rules.
3. The trap-ban table.
4. `path` rules, then `user-agent` rules, then `referrer` rules.

The first match decides. `block` returns the block response. `ban-ip` also gives the client IP a trap ban. An `ip` rule with `ban-ip` acts the same as `block`.

An allow rule beats every ban, trap bans included, on any kind. An allow rule on `user-agent` or `referrer` matches a value that any client can send, so writers should prefer `ip` allow rules.

### Readers are lenient

- A reader ignores unknown fields, so a newer writer does not break an older reader.
- A reader ignores signals, foreign kinds and actions it does not know. bantasy logs one summary line per file load, not one line per rule.
- A bad line (bad JSON, no kind, empty match, `banSeconds` below 0 or above 100 years, bad CIDR or regexp) loses only that rule. The reader logs a warning with the file and line number.
- A last line with no newline may be a write in progress. The reader loads it when it parses, and skips it with no warning when it does not. A half-written JSON object never parses.
- A reader enforces `expires`. An expired rule does not match, even when no writer has removed it. Writers own pruning.

### Tools report bad actors by appending a rule

There is no API. A tool that is sure appends a ban with an `expires`. A tool that has only evidence appends a signal. bantasy ignores the signal, but other tools can read it. Set `cause` to link a ban to the signal or rule behind it.

### Trap bans stay in memory

A `ban-ip` match puts the client IP in an in-memory table for `banSeconds`. bantasy does not write the ban to a rule file, for two reasons. ConfigMap mounts are read-only. Several Traefik pods would write at the same time.

So a trap ban is per pod and lost on restart. To make it shared and lasting, bantasy logs one JSON `trap` line (see the README, "Trap bans"). An external writer can turn it into a ban in a shared rule file, with `cause` set to the trap rule's `id`.

## Consequences

- Any tool that can append a line can ban, allow or signal. No client library is needed.
- The rule files are a shared record. Tools other than bantasy can keep foreign kinds in them, such as an email-domain denylist.
- Writers must keep files tidy. bantasy never removes expired rules from a file.

## Deferred

- Hit counting: ban after N matches in a time window.
- A shared writer that persists trap bans from the `trap` log line.
- Automatic bans from signals.
