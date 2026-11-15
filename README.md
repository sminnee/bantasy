# bantasy

bantasy is a Traefik middleware plugin that blocks requests by rules in JSONL files. Each rule matches a client IP, a path, a user-agent or a referrer. Any tool can add a rule by appending one line to a rule file. bantasy reloads the files when they change, skips expired rules, and can trap-ban the client IP of a request that matches a trap rule, in the style of fail2ban.

The rule model is the contract for every tool that reads or writes the files: [ADR 0001](docs/adr/0001-rule-model.md). The terms are in [CONTEXT.md](CONTEXT.md).

## Rules

A rule file holds one JSON rule per line:

```jsonl
{"id": "ops:203.0.113.7", "kind": "ip", "match": "203.0.113.7", "reason": "credential stuffing", "source": "ops", "expires": "2026-11-16T03:00:00Z"}
{"id": "repo:php-probe", "kind": "path", "match": "(?i)\\.php($|\\?)", "action": "ban-ip", "banSeconds": 86400, "reason": "PHP scanner", "source": "repo"}
{"id": "repo:office", "kind": "ip", "match": "198.51.100.0/24", "action": "allow", "reason": "office egress", "source": "repo"}
{"id": "repo:badbot", "kind": "user-agent", "match": "BadBot", "reason": "scraper", "source": "repo"}
{"id": "smartypants:email-domain:spam.example", "kind": "email-domain", "match": "spam.example", "action": "signal", "source": "smartypants"}
```

| Kind | Match |
|---|---|
| `ip` | IPv4 or IPv6 address or CIDR prefix. |
| `path` | Go regular expression on the decoded path, plus `?` and the raw query when there is one. |
| `user-agent` | Case-insensitive substring of `User-Agent`. |
| `referrer` | Case-insensitive substring of `Referer`. |

| Action | Effect |
|---|---|
| `block` (default) | Return the block response. |
| `allow` | Pass the request. An allow rule beats every other rule and every trap ban. |
| `ban-ip` | Block, and give the client IP a trap ban for `banSeconds` (default: `trapBanSeconds`). An `ip` rule with `ban-ip` only blocks. |
| `signal` | None. The rule is evidence for other tools. |

bantasy ignores a rule of a kind or action it does not know, such as kind `email-domain` or action `smartypants:block-signup`. Other tools can keep their records in the same files.

Optional fields: `id`, `cause` (the `id` of the rule or signal that led to this rule), `reason`, `source`, `added` and `expires` (RFC 3339). The ADR lists every field.

### Evaluation order

1. Allow rules of every kind.
2. `ip` rules.
3. Trap bans.
4. `path`, then `user-agent`, then `referrer` rules.

The first match decides.

An allow rule on `user-agent` or `referrer` matches a value that any client can send. A client that copies an allowed user-agent skips every ban, including IP bans and trap bans. Prefer `ip` allow rules.

### Reload, expiry and bad lines

- The first request after `reloadSeconds` checks the mtime and size of each file. bantasy reparses only a changed file. Other requests use the current rules while it does so.
- A rule stops matching at its `expires` time, with no file change.
- A missing file has no rules, and bantasy logs no error. A file that cannot be read keeps its previous rules, and bantasy logs an error.
- Bad lines and a last line with no newline follow the reader rules in the ADR. bantasy logs a warning with the file and line number for each bad line.

## Report a bad actor

Append a rule. A tool that is sure appends a ban with an `expires`:

```sh
echo '{"kind":"ip","match":"203.0.113.7","reason":"sign-up abuse","source":"smartypants","cause":"smartypants:email-domain:spam.example","expires":"2026-11-16T03:00:00Z"}' >> bans.jsonl
```

A tool that has only evidence appends a `signal` rule instead. A ConfigMap cannot be appended to. To write a rule to a ConfigMap, use the CLI.

## CLI

`cmd/bantasy` is a writer. It adds, removes, lists and prunes rules in rule files and ConfigMap keys, and checks local rule files. It ships with the plugin's git tags.

Install the latest release, or a pinned one:

```sh
go install github.com/sminnee/bantasy/cmd/bantasy@latest
go install github.com/sminnee/bantasy/cmd/bantasy@v0.0.2
```

`@latest` is the highest release tag. Run the same command again to upgrade. `go version -m "$(command -v bantasy)"` shows the installed version.

```
bantasy [global flags] <command> [args] [flags]

add <kind> <match>... --reason <text> [--action <a>] [--ttl 30m|24h|7d|never]
                      [--cause <id>] [--source <s>] [--id <id>]
remove <id>...
remove <kind> <match>... [--source <s>]
list
prune
check <file>...
```

Examples:

```sh
bantasy add ip 203.0.113.7 --reason "credential stuffing"
bantasy add user-agent BadBot --reason scraper --ttl 7d
bantasy remove ops:ip:203.0.113.7
bantasy --file bans.jsonl list
bantasy check patterns.jsonl
```

### Targets

A target is one rule file: a local file or one ConfigMap key.

| Flag | Target |
|---|---|
| `--file <path>` | A local file. A missing file reads as empty. A write replaces the file with one rename. There is no conflict check: the last writer wins. |
| `--configmap <namespace>/<name>:<key>` | One key of a ConfigMap. The CLI uses `kubectl`. A missing ConfigMap reads as empty, and a write creates it. |
| `--context <name>` | The kubectl context for each ConfigMap target. The default is kubectl's current context. |

`--file` and `--configmap` are repeatable, but each ConfigMap can be named once, and the global flags can go anywhere on the command line. With neither flag, writes go to `traefik/bantasy-dynamic:dynamic.jsonl`. `list` reads that target and `traefik/bantasy-static:static.jsonl`. A pod can mount a ConfigMap only from its own namespace, so the defaults are in `traefik`. Every argument after `--` is positional, for a match that starts with `-`.

A write goes to each target in turn. `list` shows each rule once per target that holds it, with the target name.

### Commands

- `add` writes one rule per match. The id is `<source>:<kind>:<match>`, or `--id` for one match. When a target already holds a rule with that id, `add` replaces that line and keeps its `added` time.
- `remove <id>...` applies when the first argument holds `:`. `remove <kind> <match>...` removes the rule with the id that `add` gives. A rule with the same match and another id belongs to another writer, so `remove` does not touch it. `remove` fails and writes nothing when no target holds one of the rules.
- `list` prints the target, id, kind, match, action, source, cause and expiry of each rule. An expiry is `-` for none and `expired` when past.
- `prune` drops expired rules.
- `check` reads local files only. It prints `file:line: reason` for each line that bantasy cannot load, including a last line that does not parse.

Each write edits only the lines of its own rules. Every other line keeps its exact text, including bad lines and the rules of other writers. Each write also drops expired rules of any writer, and ends each line with a newline. Blank lines drop.

Exit codes: 0 done, 1 refused or failed, 2 bad command line.

### Defaults and checks

`--source` defaults to `ops`. `--reason` is required. `--ttl` defaults to `24h` for `ip` and to no expiry for other kinds; `--ttl never` gives a permanent rule. `--action` is `block` (default), `allow`, `ban-ip`, `signal` or a third-party `<source>:<name>`.

`add` and `remove` check each match before the first read, so one bad match writes nothing:

| Kind | Check | Stored match |
|---|---|---|
| `ip` | An address or CIDR. Not in a non-public range (private, CGNAT, loopback, link-local, multicast, documentation, reserved). No wider than /16 for IPv4 or /32 for IPv6. | The masked prefix. One address is stored bare. |
| `path` | A Go regular expression. | As given. |
| `user-agent`, `referrer` | 4 to 200 characters after trim, with no control character. | Trimmed, case kept. |
| `email-domain` | A domain of two or more labels. | Lower-case, with no trailing dot. |

The id has the match in lower case for `user-agent`, `referrer` and `email-domain`, so a change of case keeps the id.

### Conflicts

The CLI reads each ConfigMap, then writes it back with `kubectl replace` and the `resourceVersion` it read. When another writer changed the ConfigMap in between, the API server refuses the write. The CLI then stops with an error that names the target, and writes no more targets. The targets before it stay written. Run the command again. A create that finds the ConfigMap already there is a conflict too.

### A wrapper for one cluster

Pin the tag and the context in a script:

```sh
#!/bin/sh
exec go run github.com/sminnee/bantasy/cmd/bantasy@v0.0.2 --context prod-cluster "$@"
```

The script uses the default targets. Do not pin both ConfigMaps with `--configmap`: then `add` writes to both.

## Trap bans

A `ban-ip` match blocks the request and bans the client IP for `banSeconds`. The ban is held in memory. Each Traefik pod has its own trap-ban table, and a restart clears it. The table holds at most `trapBanMax` entries. When it is full, bantasy drops expired entries (at most once a minute), then any one entry.

A trap ban holds one exact address. An IPv6 client can move to another address in its own /64 and escape it.

For each trap ban, bantasy logs one JSON line to stdout:

```json
{"plugin":"bantasy","event":"trap","clientIp":"192.0.2.20","id":"repo:php-probe","banSeconds":86400,"expires":"2026-11-16T03:00:00Z","reason":"PHP scanner","middleware":"bantasy@file"}
```

To make a trap ban shared and lasting, an external writer can turn this line into a ban in a rule file, with `cause` set to the trap rule's `id`.

## Log lines

bantasy logs one JSON object per line to stdout. It leaves out fields with an empty value.

A block, when `logBlocks` is on:

```json
{"plugin":"bantasy","event":"block","middleware":"bantasy@file","action":"block","kind":"ip","match":"203.0.113.7","id":"ops:203.0.113.7","cause":"smartypants:email-domain:spam.example","reason":"sign-up abuse","source":"ops","clientIp":"203.0.113.7","uri":"/signup"}
```

A block by a trap ban has `action` `trap-ban`, no `id`, `kind` or `match`, and the trap rule's `id` in `cause`. The trap line is shown under "Trap bans".

A rule-file problem has `level` (`info`, `warn` or `error`), `file` and `msg`.

## Configuration

| Key | Default | Meaning |
|---|---|---|
| `files` | none (required) | Paths of rule files. |
| `reloadSeconds` | `10` | Time between file checks. `0` checks on every request. |
| `statusCode` | `403` | Status of the block response. |
| `body` | `""` | Plain-text body of the block response. |
| `clientIpHeader` | `""` | Header that holds the client IP, such as `X-Real-Ip`. It must hold one value that a trusted proxy sets. bantasy uses its first comma-separated value. Empty, missing or bad: bantasy uses the request's remote address. |
| `logBlocks` | `true` | Log one JSON line per blocked request. |
| `trapBanSeconds` | `3600` | Trap-ban time for a `ban-ip` rule with no `banSeconds`. |
| `trapBanMax` | `10000` | Maximum entries in the trap-ban table. |

All Middlewares with the same `files`, `reloadSeconds` and `trapBanMax` share one rule set and one trap-ban table. A trap on one route bans the IP on all of them.

Traefik replaces `X-Real-Ip` with the remote address unless the entry point trusts the sender. Behind a CDN, set `forwardedHeaders.trustedIPs` on the entry point to the CDN's ranges. Do not use `X-Forwarded-For`: its first value is whatever the client sent.

## Kubernetes example

Two ConfigMaps in the `traefik` namespace: `bantasy-static` holds rules kept in a repo, and `bantasy-dynamic` holds rules that tools write. These are the CLI's default targets.

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: bantasy-static
  namespace: traefik
data:
  static.jsonl: |
    {"id":"repo:php-probe","kind":"path","match":"(?i)\\.php($|\\?)","action":"ban-ip","reason":"PHP scanner","source":"repo"}
---
apiVersion: v1
kind: ConfigMap
metadata:
  name: bantasy-dynamic
  namespace: traefik
data:
  dynamic.jsonl: ""
```

Traefik Helm chart values:

```yaml
experimental:
  plugins:
    bantasy:
      moduleName: github.com/sminnee/bantasy
      version: v0.0.2
volumes:
  - name: bantasy-static
    mountPath: /etc/bantasy/static
    type: configMap
  - name: bantasy-dynamic
    mountPath: /etc/bantasy/dynamic
    type: configMap
```

Middleware:

```yaml
apiVersion: traefik.io/v1alpha1
kind: Middleware
metadata:
  name: bantasy
  namespace: traefik
spec:
  plugin:
    bantasy:
      files:
        - /etc/bantasy/static/static.jsonl
        - /etc/bantasy/dynamic/dynamic.jsonl
      clientIpHeader: X-Real-Ip
```

The kubelet updates a mounted ConfigMap within about a minute of a write. bantasy picks up the change at its next check.

## Development

```sh
make lint test yaegi_test
make race   # needs a C compiler
```

`yaegi_test` runs the test suite in Yaegi, the Go interpreter that Traefik uses to run plugins. The plugin must use only the Go standard library. The CLI in `cmd/bantasy` is compiled Go, and Yaegi never loads it.
