@.claude/CLAUDE.local.md

# bantasy

bantasy is a behaviour-based banning plugin for Traefik: a middleware that blocks requests by rules read from JSONL rule files. `README.md` covers use; `docs/adr/0001-rule-model.md` is the rule-file contract; `CONTEXT.md` is the glossary.

## Commands

Go 1.27, golangci-lint v2 and yaegi v0.16.3 (the versions Traefik v3.7 uses).

- `make lint` — `golangci-lint run`
- `make test` — `go test -v -cover ./...`
- `make race` — `go test -race ./...`; needs a C compiler, runs in CI
- `make yaegi_test` — `yaegi test -v .`, the suite under Traefik's plugin interpreter
- `golangci-lint fmt` — format

Without `make`, run the commands directly. `make lint`, `make test` and `make yaegi_test` must pass.

## Architecture

The plugin is one package at the repo root, stdlib only, no `unsafe`, no cgo.

- `bantasy.go` — `Config`, `CreateConfig`, `New`, `ServeHTTP`: client IP, applies the decision (trap ban, block response), JSON log lines.
- `decide.go` — `decide`: the whole evaluation order, with no side effects.
- `registry.go` — the rule set and trap-ban table shared per config.
- `ruleset.go` — the rule set: lazy reload from the request path (try-lock, mtime + size), expiry-driven recompile, injectable clock.
- `rules.go` — JSONL parse with per-line warnings, `compile` to allow and block lists, `match`.
- `iprange.go` — IP prefixes as sorted 16-byte ranges with a running max end.
- `trapban.go` — the bounded in-memory trap-ban table.
- `conformance_test.go` — runs `parseRule` over `cmd/bantasy/testdata/lines.jsonl`.

`cmd/bantasy/` is the rule CLI, a separate `package main`, stdlib only. The plugin never imports it, so Yaegi never loads it, and the Yaegi constraints below do not apply to it.

- `main.go` — `run(args, env)`, flag parse with flags after positionals, exit codes.
- `commands.go` — `add`, `remove`, `list`, `prune`, `check`; default targets.
- `target.go` — `fileTarget` (atomic rename) and `configMapTarget` (`kubectl get`, then `replace` with the `resourceVersion` it read).
- `lines.go` — a rule file as lines: `parseLines`, `render`, `prune`, `upsert`, `removeIDs`.
- `validate.go` — the `add` checks, `parseTTL`, `ruleID`, and `checkLine`, a copy of the plugin's `parseRule`. `testdata/lines.jsonl` and `lines.want` keep the copy in step: change both packages together.

## Yaegi constraints

Traefik runs the plugin in Yaegi, not compiled Go. Every change to the root package must pass `make yaegi_test`.

- No generics, `slices` or `maps` packages, `min`/`max` builtins or range over int.
- No tuple assignment to struct fields (`f.a, f.b = x, y`): Yaegi drops values. Assign one field per statement.
- Do not forward a call's results through a type change (`return newBantasy(...)` from `New`): Yaegi loses the error. Assign the results, then return `nil, err`.
- No background goroutines: Traefik rebuilds Middlewares on each config change, and a goroutine per instance leaks.
