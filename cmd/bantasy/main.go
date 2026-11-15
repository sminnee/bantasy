// Command bantasy adds, removes, lists, prunes and checks rules in bantasy
// rule files: local files and ConfigMap keys.
package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"time"
)

const usage = `Usage: bantasy [global flags] <command> [args] [flags]

Commands:
  add <kind> <match>... --reason <text> [--action <a>] [--ttl 30m|24h|7d|never]
                        [--cause <id>] [--source <s>] [--id <id>]
  remove <id>...
  remove <kind> <match>... [--source <s>]
  list
  prune
  check <file>...
  ipinfo <address>

Global flags (allowed anywhere):
  --file <path>                         a local rule file (repeatable)
  --configmap <namespace>/<name>:<key>  a ConfigMap key (repeatable)
  --context <name>                      kubectl context (default: kubectl's current context)

With no --file or --configmap, writes go to traefik/bantasy-dynamic:dynamic.jsonl,
and list reads that and traefik/bantasy-static:static.jsonl.

Kinds: ip, path, user-agent, referrer, email-domain.
Actions: block (default), allow, ban-ip, signal, <source>:<name>.
--source defaults to ops. --ttl defaults to 24h for ip and to never for other kinds.
`

// env is what run needs from the world. Tests replace each part.
type env struct {
	stdout, stderr io.Writer
	now            func() time.Time
	kubectl        kubectlFunc
	rdap           rdapClient
}

func (e env) outf(format string, a ...any) { _, _ = fmt.Fprintf(e.stdout, format, a...) }

func (e env) errf(format string, a ...any) { _, _ = fmt.Fprintf(e.stderr, format, a...) }

// usageError is a bad command line. run exits 2 for it.
type usageError struct{ msg string }

func (e *usageError) Error() string { return e.msg }

func usagef(format string, a ...any) error {
	return &usageError{msg: fmt.Sprintf(format, a...)}
}

// stringList is a repeatable string flag.
type stringList []string

func (s *stringList) String() string { return strings.Join(*s, ",") }

func (s *stringList) Set(v string) error {
	*s = append(*s, v)
	return nil
}

// options holds every flag. set names the flags given.
type options struct {
	files, configMaps stringList
	context           string

	reason, action, ttl, cause, source, id string

	set map[string]bool
}

// commandFlags are the flags each command accepts, besides the global ones.
var commandFlags = map[string][]string{
	"add":    {"reason", "action", "ttl", "cause", "source", "id"},
	"remove": {"source"},
	"list":   nil,
	"prune":  nil,
	"check":  nil,
	"ipinfo": nil,
}

var globalFlags = []string{"file", "configmap", "context"}

func main() {
	e := env{stdout: os.Stdout, stderr: os.Stderr, now: time.Now, kubectl: execKubectl, rdap: defaultRDAPClient()}
	os.Exit(run(os.Args[1:], e))
}

// run runs one command and returns the exit code: 0 done, 1 refused or
// failed, 2 usage error.
func run(args []string, e env) int {
	cmd, pos, opts, err := parseArgs(args)
	if errors.Is(err, flag.ErrHelp) {
		e.outf("%s", usage)
		return 0
	}

	if err == nil {
		err = dispatch(cmd, pos, opts, e)
	}

	var ue *usageError

	switch {
	case err == nil:
		return 0
	case errors.As(err, &ue):
		e.errf("bantasy: %v\n\n%s", err, usage)
		return 2
	default:
		e.errf("bantasy: %v\n", err)
		return 1
	}
}

func dispatch(cmd string, pos []string, opts *options, e env) error {
	switch cmd {
	case "add":
		return runAdd(pos, opts, e)
	case "remove":
		return runRemove(pos, opts, e)
	case "list":
		return runList(pos, opts, e)
	case "prune":
		return runPrune(pos, opts, e)
	case "ipinfo":
		return runIpinfo(pos, e)
	default:
		return runCheck(pos, e)
	}
}

func newFlagSet(o *options) *flag.FlagSet {
	fs := flag.NewFlagSet("bantasy", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	fs.Var(&o.files, "file", "")
	fs.Var(&o.configMaps, "configmap", "")
	fs.StringVar(&o.context, "context", "", "")
	fs.StringVar(&o.reason, "reason", "", "")
	fs.StringVar(&o.action, "action", "", "")
	fs.StringVar(&o.ttl, "ttl", "", "")
	fs.StringVar(&o.cause, "cause", "", "")
	fs.StringVar(&o.source, "source", "", "")
	fs.StringVar(&o.id, "id", "", "")

	return fs
}

// parseArgs reads the command line. Flags may come before or after the
// positionals; every argument after "--" is positional.
func parseArgs(args []string) (string, []string, *options, error) {
	o := &options{set: map[string]bool{}}
	fs := newFlagSet(o)

	var rest []string

	for i, a := range args {
		if a == "--" {
			rest = args[i+1:]
			args = args[:i]

			break
		}
	}

	var pos []string

	for {
		if err := fs.Parse(args); err != nil {
			if errors.Is(err, flag.ErrHelp) {
				return "", nil, nil, err
			}

			return "", nil, nil, usagef("%v", err)
		}

		args = fs.Args()
		if len(args) == 0 {
			break
		}

		pos = append(pos, args[0])
		args = args[1:]
	}

	pos = append(pos, rest...)

	fs.Visit(func(f *flag.Flag) { o.set[f.Name] = true })

	if len(pos) == 0 {
		return "", nil, nil, usagef("no command")
	}

	cmd := pos[0]

	allowed, ok := commandFlags[cmd]
	if !ok {
		return "", nil, nil, usagef("unknown command %q", cmd)
	}

	if err := checkFlags(cmd, allowed, o.set); err != nil {
		return "", nil, nil, err
	}

	return cmd, pos[1:], o, nil
}

func checkFlags(cmd string, allowed []string, set map[string]bool) error {
	ok := map[string]bool{}
	for _, f := range allowed {
		ok[f] = true
	}

	// check and ipinfo touch no target.
	if cmd != "check" && cmd != "ipinfo" {
		for _, f := range globalFlags {
			ok[f] = true
		}
	}

	var bad []string

	for f := range set {
		if !ok[f] {
			bad = append(bad, "--"+f)
		}
	}

	if len(bad) > 0 {
		sort.Strings(bad)
		return usagef("%s does not take %s", cmd, strings.Join(bad, ", "))
	}

	return nil
}
