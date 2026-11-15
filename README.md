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

A tool that has only evidence appends a `signal` rule instead. A ConfigMap cannot be appended to; the ADR says how to write one.

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

Two ConfigMaps in the `traefik` namespace: `edge-ban-patterns` holds rules kept in a repo, and `edge-bans` holds bans that tools write.

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: edge-ban-patterns
  namespace: traefik
data:
  patterns.jsonl: |
    {"id":"repo:php-probe","kind":"path","match":"(?i)\\.php($|\\?)","action":"ban-ip","reason":"PHP scanner","source":"repo"}
---
apiVersion: v1
kind: ConfigMap
metadata:
  name: edge-bans
  namespace: traefik
data:
  bans.jsonl: ""
```

Traefik Helm chart values:

```yaml
experimental:
  plugins:
    bantasy:
      moduleName: github.com/sminnee/bantasy
      version: v0.1.0
volumes:
  - name: edge-ban-patterns
    mountPath: /etc/bantasy/patterns
    type: configMap
  - name: edge-bans
    mountPath: /etc/bantasy/bans
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
        - /etc/bantasy/patterns/patterns.jsonl
        - /etc/bantasy/bans/bans.jsonl
      clientIpHeader: X-Real-Ip
```

The kubelet updates a mounted ConfigMap within about a minute of a write. bantasy picks up the change at its next check.

## Development

```sh
make lint test yaegi_test
make race   # needs a C compiler
```

`yaegi_test` runs the test suite in Yaegi, the Go interpreter that Traefik uses to run plugins. The plugin must use only the Go standard library.
