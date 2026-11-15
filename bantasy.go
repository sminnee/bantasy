// Package bantasy is a Traefik middleware plugin that blocks requests by
// rules read from JSONL rule files. See docs/adr/0001-rule-model.md.
package bantasy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/netip"
	"os"
	"strings"
	"time"
)

// The static and dynamic rule files. See CONTEXT.md and ADR 0002.
const (
	defaultStaticFile  = "/etc/bantasy/static/static.jsonl"
	defaultDynamicFile = "/etc/bantasy/dynamic/dynamic.jsonl"
)

// Config is the plugin configuration.
type Config struct {
	Files          []string `json:"files,omitempty"`
	ReloadSeconds  int      `json:"reloadSeconds,omitempty"`
	StatusCode     int      `json:"statusCode,omitempty"`
	Body           string   `json:"body,omitempty"`
	ClientIPHeader string   `json:"clientIpHeader,omitempty"`
	LogBlocks      bool     `json:"logBlocks,omitempty"`
	TrapBanSeconds int      `json:"trapBanSeconds,omitempty"`
	TrapBanMax     int      `json:"trapBanMax,omitempty"`
}

// CreateConfig returns the default plugin configuration.
func CreateConfig() *Config {
	return &Config{
		ReloadSeconds:  10,
		StatusCode:     http.StatusForbidden,
		LogBlocks:      true,
		TrapBanSeconds: 28800,
		TrapBanMax:     10000,
	}
}

// logger writes one JSON object per line to stdout, where Traefik collects
// plugin output.
var logger = log.New(os.Stdout, "", 0)

// Bantasy is the middleware.
type Bantasy struct {
	next    http.Handler
	name    string
	config  Config
	rules   *ruleSet
	traps   *trapTable
	now     func() time.Time
	trapBan time.Duration
}

// New makes a bantasy middleware.
func New(_ context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {
	b, err := newBantasy(next, config, name, time.Now)
	if err != nil {
		// Explicit nil: under Yaegi, `return newBantasy(...)` loses err.
		return nil, err
	}

	return b, nil
}

func newBantasy(next http.Handler, config *Config, name string, now func() time.Time) (*Bantasy, error) {
	if err := validate(config); err != nil {
		return nil, fmt.Errorf("bantasy %s: %w", name, err)
	}

	cfg := *config

	defaulted := len(cfg.Files) == 0
	if defaulted {
		// The default is set here, not in CreateConfig, so that no list
		// merge in Traefik can join it to the user's files.
		cfg.Files = []string{defaultStaticFile, defaultDynamicFile}
	}

	s := sharedState(cfg.Files, defaulted, time.Duration(cfg.ReloadSeconds)*time.Second, cfg.TrapBanMax, now)

	b := &Bantasy{
		next:    next,
		name:    name,
		config:  cfg,
		trapBan: time.Duration(cfg.TrapBanSeconds) * time.Second,
		rules:   s.rules,
		traps:   s.traps,
		now:     now,
	}

	return b, nil
}

func validate(c *Config) error {
	switch {
	case c.ReloadSeconds < 0:
		return errors.New("reloadSeconds is negative")
	case c.StatusCode < 100 || c.StatusCode > 599:
		return fmt.Errorf("statusCode %d is not an HTTP status", c.StatusCode)
	case c.TrapBanSeconds <= 0 || c.TrapBanSeconds > maxBanSeconds:
		return fmt.Errorf("trapBanSeconds must be 1 to %d", maxBanSeconds)
	case c.TrapBanMax <= 0:
		return errors.New("trapBanMax must be positive")
	}

	return nil
}

func (b *Bantasy) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	ip := b.clientAddr(req)
	in := newRequest(ip, matchURI(req), req.UserAgent(), req.Referer())
	d := decide(b.rules.current(), b.traps, in, b.now())

	if d.lift != nil {
		b.pardon(ip, d)
	}

	switch d.action {
	case "", actionAllow:
		b.next.ServeHTTP(rw, req)

		return
	case actionBanIP:
		if ip.IsValid() {
			b.trap(ip, d.rule)
		}
	}

	b.block(rw, req, ip, d)
}

// trap puts ip in the trap-ban table and logs a trap line.
func (b *Bantasy) trap(ip netip.Addr, r *rule) {
	d := b.trapBan
	if r.BanSeconds > 0 {
		d = time.Duration(r.BanSeconds) * time.Second
	}

	now := b.now()
	b.traps.add(ip, trapBan{expires: now.Add(d), set: now, rule: r}, now)

	logEvent(map[string]any{
		"event":      "trap",
		"middleware": b.name,
		"clientIp":   ip.String(),
		"id":         r.ID,
		"reason":     r.Reason,
		"banSeconds": int(d / time.Second),
		"expires":    now.Add(d).UTC().Format(time.RFC3339),
	})
}

// pardon removes ip's lifted trap ban and logs a pardon line. It runs before
// trap: add keeps an existing entry with a later expiry, and that entry's old
// set time would let the pardon lift the new ban too.
func (b *Bantasy) pardon(ip netip.Addr, d decision) {
	if !b.traps.removeIf(ip, d.lifted.set) {
		return
	}

	logEvent(map[string]any{
		"event":      "pardon",
		"middleware": b.name,
		"clientIp":   ip.String(),
		"id":         d.lift.ID,
		"cause":      d.lifted.rule.ID,
	})
}

func (b *Bantasy) block(rw http.ResponseWriter, req *http.Request, ip netip.Addr, d decision) {
	r := d.rule

	if b.config.LogBlocks {
		ev := map[string]any{
			"event":      "block",
			"middleware": b.name,
			"action":     d.action,
			"reason":     r.Reason,
			"source":     r.Source,
			"uri":        req.URL.RequestURI(),
		}

		if d.action == actionTrapBan {
			// This request did not match the trap rule; the trap rule is
			// the cause of the ban.
			ev["cause"] = r.ID
		} else {
			ev["kind"] = r.Kind
			ev["match"] = r.Match
			ev["id"] = r.ID
			ev["cause"] = r.Cause
		}

		if ip.IsValid() {
			ev["clientIp"] = ip.String()
		}

		logEvent(ev)
	}

	if b.config.Body != "" {
		rw.Header().Set("Content-Type", "text/plain; charset=utf-8")
	}

	rw.WriteHeader(b.config.StatusCode)

	if b.config.Body != "" {
		_, _ = rw.Write([]byte(b.config.Body))
	}
}

// matchURI is what path rules match: the decoded path, plus "?" and the raw
// query when there is one. The path is decoded so that an encoded name (such
// as /index%2Ephp) cannot dodge a rule; the backend decodes it too.
func matchURI(req *http.Request) string {
	if req.URL.RawQuery == "" {
		return req.URL.Path
	}

	return req.URL.Path + "?" + req.URL.RawQuery
}

// clientAddr returns the client IP: the first token of the configured
// header, else the host of RemoteAddr. It returns an invalid Addr when
// neither parses.
func (b *Bantasy) clientAddr(req *http.Request) netip.Addr {
	if b.config.ClientIPHeader != "" {
		v := req.Header.Get(b.config.ClientIPHeader)
		if i := strings.IndexByte(v, ','); i >= 0 {
			v = v[:i]
		}

		if a, err := netip.ParseAddr(strings.TrimSpace(v)); err == nil {
			return a.Unmap().WithZone("")
		}
	}

	host, _, err := net.SplitHostPort(req.RemoteAddr)
	if err != nil {
		host = req.RemoteAddr
	}

	a, err := netip.ParseAddr(host)
	if err != nil {
		return netip.Addr{}
	}

	return a.Unmap().WithZone("")
}

func logEvent(ev map[string]any) {
	ev["plugin"] = "bantasy"

	for k, v := range ev {
		if s, ok := v.(string); ok && s == "" {
			delete(ev, k)
		}
	}

	line, err := json.Marshal(ev)
	if err != nil {
		return
	}

	logger.Println(string(line))
}

func logInfo(file, msg string) { logEvent(map[string]any{"level": "info", "file": file, "msg": msg}) }

func logWarn(file, msg string) { logEvent(map[string]any{"level": "warn", "file": file, "msg": msg}) }

func logError(file, msg string) { logEvent(map[string]any{"level": "error", "file": file, "msg": msg}) }
