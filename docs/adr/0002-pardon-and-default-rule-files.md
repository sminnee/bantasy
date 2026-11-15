# ADR 0002: Pardons and the default rule files

Status: accepted, 2026-11-15.

## Context

A trap ban had no undo. It stayed until it expired or the Traefik pod restarted. A person who tests a trap rule bans their own IP for hours.

Rule files also had no fixed home. Each install chose its own ConfigMaps and paths, so no tool could edit them without config.

This ADR extends [ADR 0001](0001-rule-model.md). The terms are in `CONTEXT.md`.

## Decision

### A pardon rule lifts a trap ban

A pardon is an `ip` rule with action `pardon` and an `added` time:

```jsonl
{"id":"ops:pardon:192.0.2.20","kind":"ip","match":"192.0.2.20","action":"pardon","added":"2026-11-15T03:00:00.123456789Z","expires":"2026-11-16T03:00:00Z"}
```

| Rule | Effect |
|---|---|
| Kind | Must be `ip`. The match is an address or a CIDR prefix. |
| `added` | Required. The pardon lifts only trap bans set before this time. |
| `expires` | Optional. An expired pardon lifts nothing. |
| Other kinds, or no `added` | A bad line. The reader logs a warning. |

When a request hits a trap ban (step 3 of the evaluation order), bantasy checks the pardons. When a pardon matches the client IP, and the ban was set before the pardon's `added`, bantasy removes the trap ban. It logs one `pardon` line, and goes on to step 4 as if there was no ban. A later trap rule match bans the IP again.

The `added` limit is the reason a pardon is not an allow rule. An allow rule passes every later bad request too, so a person cannot test the trap again until they remove the rule. A pardon is used once per ban.

A pardon does not lift `ip` block rules. They are lines in a rule file: to undo one, a writer removes the line.

bantasy compares `added` with its own clock. A writer sets `added` to the current time, with nanoseconds. When the writer's clock is ahead of the pod's clock, a new trap ban in that gap is also lifted.

A pardon with an `added` more than 5 minutes after the pod's clock lifts nothing until the clock catches up, and bantasy logs a warning when it loads the pardon. Without this limit, a wrong `added` (a typo, a bad clock) would lift every trap ban on its range until that time. The 5 minutes allow for normal clock skew.

### Pardons are rules, not an API

bantasy has no listener and starts no goroutine: Traefik runs it in Yaegi and makes each Middleware again on each config change. A pardon in a rule file reaches every pod through the normal reload. Trap bans stay in memory, as ADR 0001 says.

### The static and the dynamic rule file

When `files` is empty, bantasy reads two default rule files:

| Rule file | ConfigMap key (namespace `traefik`) | Path |
|---|---|---|
| Static rule file | `bantasy-static:static.jsonl` | `/etc/bantasy/static/static.jsonl` |
| Dynamic rule file | `bantasy-dynamic:dynamic.jsonl` | `/etc/bantasy/dynamic/dynamic.jsonl` |

These are the CLI's default targets, so the plugin and the CLI need no config to agree.

The static rule file is kept in a repo and deployed with the cluster config. It holds trap rules, allow rules and lasting bans. The dynamic rule file is written at run time. It holds bans and pardons that a person or a tool adds.

bantasy applies the default when it makes the Middleware, not in `CreateConfig`. So a `files` list in the Traefik config replaces the default and is never merged with it.

An empty `files` is no longer a config error. So bantasy logs each rule file it reads at start, marked `(default)` when it comes from the default, and a missing rule file logs one warning at its first check. Without these lines, an install whose ConfigMaps are not mounted would pass all traffic and log nothing.

The default `trapBanSeconds` is 8 hours (28800), up from 1 hour, as the operator asked: a trap ban should keep a bad bot out for a working day. An install that sets no `trapBanSeconds` now gives 8-hour trap bans; set `trapBanSeconds: 3600` to keep the old time.

### The CLI writes the dynamic rule file

The CLI, `cmd/bantasy`, writes the dynamic rule file by default and never needs to write the static one. Its line check mirrors the plugin's, so it accepts a pardon line with the same rules.

## Consequences

- A person can undo a trap ban and test the trap again, with no restart.
- A pardon takes effect after the kubelet updates the mount and bantasy reloads: about a minute.
- Pardons stay in the dynamic rule file until they expire or a writer prunes them. A pardon with no `expires` is harmless, because it lifts only bans set before its `added`.
- A trap ban is still per pod and lost on restart.
