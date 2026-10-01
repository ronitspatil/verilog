// Package redact removes credentials and API keys of RPC URLs from log
// lines and error messages.
//
// Hosted RPC providers put the secret in the userinfo
// (https://user:pass@host), in a query parameter (?apikey=..., ?dkey=...)
// or as a path segment (Infura /v3/<id>, Alchemy /v2/<key>, QuickNode
// /<token>/, Ankr /eth/<key>, Chainstack, BlastAPI, GetBlock, ...). All of
// these are replaced with "REDACTED".
package redact

import (
	"context"
	"log/slog"
	"net/url"
	"regexp"
	"slices"
	"strings"
)

// Mask replaces each secret.
const Mask = "REDACTED"

// minTokenLen is the shortest path segment treated as an API key. Provider
// keys are 32+ characters; path words such as "v3", "eth" or "rpc" are not.
const minTokenLen = 16

var tokenSegment = regexp.MustCompile(`^[A-Za-z0-9_\-]+$`)

// URL returns raw with every secret replaced, for logging the URL itself.
// An unparseable URL is replaced entirely.
func URL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" && u.Opaque != "" {
		return Mask
	}
	if u.User != nil {
		u.User = url.User(Mask)
	}
	if u.RawQuery != "" {
		q := u.Query()
		for k := range q {
			q[k] = []string{Mask}
		}
		u.RawQuery = q.Encode()
	}
	segs := strings.Split(u.Path, "/")
	for i, s := range segs {
		if isToken(s) {
			segs[i] = Mask
		}
	}
	u.Path = strings.Join(segs, "/")
	u.RawPath = ""
	u.Fragment = ""
	u.RawFragment = ""
	return u.String()
}

// secretParam reports whether a query parameter name usually carries a
// credential (apikey, api_key, key, token, access_token, dkey, auth, ...).
func secretParam(k string) bool {
	k = strings.ToLower(k)
	for _, w := range []string{"key", "token", "auth", "secret", "pass", "sig", "credential"} {
		if strings.Contains(k, w) {
			return true
		}
	}
	return false
}

func isToken(s string) bool { return len(s) >= minTokenLen && tokenSegment.MatchString(s) }

// Secrets returns the secret substrings of raw (userinfo, query values,
// token-like path segments), in raw and escaped forms, longest first.
func Secrets(raw string) []string {
	u, err := url.Parse(raw)
	if err != nil {
		return []string{raw}
	}
	var out []string
	add := func(s string) {
		if len(s) < 4 { // too short to be a secret; replacing it would mangle text
			return
		}
		out = append(out, s, url.QueryEscape(s), url.PathEscape(s))
	}
	if u.User != nil {
		add(u.User.Username())
		if p, ok := u.User.Password(); ok {
			add(p)
		}
		add(u.User.String())
	}
	// Query values: those of secret-looking parameters, and any long token.
	// (URL redacts every query value; free text keeps short harmless values
	// such as network=ethereum readable.)
	for k, vs := range u.Query() {
		for _, v := range vs {
			if secretParam(k) || isToken(v) {
				add(v)
			}
		}
	}
	if u.RawQuery != "" {
		for _, kv := range strings.Split(u.RawQuery, "&") {
			if k, v, ok := strings.Cut(kv, "="); ok && (secretParam(k) || isToken(v)) {
				add(v)
			}
		}
	}
	for _, s := range strings.Split(u.EscapedPath(), "/") {
		if isToken(s) {
			add(s)
		}
	}
	for _, s := range strings.Split(u.Path, "/") {
		if isToken(s) {
			add(s)
		}
	}
	slices.SortFunc(out, func(a, b string) int { return len(b) - len(a) })
	return slices.Compact(out)
}

// Redactor replaces the secrets of a set of URLs in arbitrary text.
type Redactor struct {
	r *strings.Replacer
}

// New returns a Redactor for the given URLs.
func New(urls ...string) *Redactor {
	var pairs []string
	for _, u := range urls {
		for _, s := range Secrets(u) {
			pairs = append(pairs, s, Mask)
		}
	}
	if len(pairs) == 0 {
		return &Redactor{}
	}
	return &Redactor{r: strings.NewReplacer(pairs...)}
}

// String redacts s.
func (r *Redactor) String(s string) string {
	if r == nil || r.r == nil {
		return s
	}
	return r.r.Replace(s)
}

// Error returns err with a redacted message. errors.Is and errors.As still
// see the original chain.
func (r *Redactor) Error(err error) error {
	if err == nil {
		return nil
	}
	msg := err.Error()
	red := r.String(msg)
	if red == msg {
		return err
	}
	return &redactedError{msg: red, err: err}
}

type redactedError struct {
	msg string
	err error
}

func (e *redactedError) Error() string { return e.msg }
func (e *redactedError) Unwrap() error { return e.err }

// Handler wraps a slog.Handler and redacts the message and every attribute
// (strings, errors, Stringers and anything else rendered to text).
func (r *Redactor) Handler(h slog.Handler) slog.Handler {
	return &handler{h: h, r: r}
}

type handler struct {
	h slog.Handler
	r *Redactor
}

func (h *handler) Enabled(ctx context.Context, l slog.Level) bool { return h.h.Enabled(ctx, l) }

func (h *handler) Handle(ctx context.Context, rec slog.Record) error {
	out := slog.NewRecord(rec.Time, rec.Level, h.r.String(rec.Message), rec.PC)
	rec.Attrs(func(a slog.Attr) bool {
		out.AddAttrs(h.attr(a))
		return true
	})
	return h.h.Handle(ctx, out)
}

func (h *handler) WithAttrs(as []slog.Attr) slog.Handler {
	red := make([]slog.Attr, len(as))
	for i, a := range as {
		red[i] = h.attr(a)
	}
	return &handler{h: h.h.WithAttrs(red), r: h.r}
}

func (h *handler) WithGroup(name string) slog.Handler {
	return &handler{h: h.h.WithGroup(name), r: h.r}
}

func (h *handler) attr(a slog.Attr) slog.Attr {
	v := a.Value.Resolve()
	switch v.Kind() {
	case slog.KindString:
		return slog.String(a.Key, h.r.String(v.String()))
	case slog.KindGroup:
		g := v.Group()
		red := make([]any, len(g))
		for i, ga := range g {
			red[i] = h.attr(ga)
		}
		return slog.Group(a.Key, red...)
	case slog.KindAny:
		if err, ok := v.Any().(error); ok {
			return slog.String(a.Key, h.r.String(err.Error()))
		}
		s := v.String() // fmt.Sprint of the value
		if red := h.r.String(s); red != s {
			return slog.String(a.Key, red)
		}
		return slog.Attr{Key: a.Key, Value: v}
	default:
		return slog.Attr{Key: a.Key, Value: v}
	}
}
