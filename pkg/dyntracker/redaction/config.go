// Package redaction provides explicitly configured, streaming content masking
// for the container-log diagnostic pipeline.
//
// Redaction is opt-in: a nil Config (or one without rules) changes nothing and
// the pipeline output stays byte-identical to the unconfigured behavior.
//
// Scope and guarantees (see README.md for the full description):
//
//   - Rules are supplied by the caller as regular expressions or fixed text.
//     There is no automatic detection of arbitrary secrets.
//   - Only the log message body is matched. The timestamp prefix and the
//     pod/container source identifiers are never modified or matched.
//   - Rules never delete lines: every match is replaced with a marker, the
//     unmatched remainder of every line is preserved verbatim.
//   - Rules are applied in configuration order. At each position the first
//     rule whose pattern matches wins; already masked spans are never matched
//     again, so re-applying redaction to its own output is idempotent.
//   - Cross-line matching is bounded by MaxWindowLines and MaxWindowBytes.
//     A multiline secret whose closing part never arrives within the window
//     cannot hold buffering forever: lines leave the window (and are emitted)
//     once the bounds are reached.
package redaction

import (
	"fmt"
	"regexp"
)

// DefaultReplacement is the marker emitted in place of a matched value when a
// rule does not define its own replacement.
const DefaultReplacement = "[REDACTED]"

const (
	// DefaultMaxWindowLines bounds how many log lines a multiline rule may
	// span. Beyond this, the oldest buffered lines are emitted (after the
	// single-line rules have been applied) even if no end marker arrived.
	DefaultMaxWindowLines = 16

	// DefaultMaxWindowBytes bounds the total byte size of the multiline
	// window, using the same order of magnitude as the tracker line limit.
	DefaultMaxWindowBytes = 1 * 1024 * 1024

	// maxAllowedWindowBytes is the hard upper bound accepted from
	// configuration. It keeps a misconfigured window from pinning unbounded
	// amounts of unredacted content in memory.
	maxAllowedWindowBytes = 16 * 1024 * 1024
)

// RuleKind selects how a Rule pattern is interpreted.
type RuleKind int

const (
	// KindRegexp treats Pattern as a Go RE2 regular expression applied to the
	// message body (or to a bounded multiline window when Multiline is set).
	KindRegexp RuleKind = iota

	// KindLiteral treats Pattern as fixed text matched verbatim.
	KindLiteral
)

// Rule is a single, explicitly configured masking rule.
type Rule struct {
	// Name identifies the rule in validation errors. It is optional but must
	// be unique among named rules when set.
	Name string

	// Kind selects regexp or literal matching.
	Kind RuleKind

	// Pattern is the regexp source (KindRegexp) or the literal text
	// (KindLiteral). Empty patterns are rejected.
	Pattern string

	// Multiline allows the rule to match across line boundaries. Only regexp
	// rules may be multiline; a multiline literal rule is rejected. Matching
	// stays confined to the bounded window defined by the Config.
	Multiline bool

	// Replacement overrides DefaultReplacement for this rule. Replacements
	// are emitted verbatim (no regexp expansion).
	Replacement string

	// captureGroup, when > 0, makes the rule keep the numbered capture group
	// of every match verbatim and replace only the remainder of the match.
	// Used by KeyValueRule to preserve the "key=" prefix. Not part of the
	// public Rule literal API: set it through the provided constructors.
	captureGroup int
}

// Config is the validated redaction configuration. Build it with NewConfig;
// the zero value / nil Config means redaction is disabled.
type Config struct {
	rules          []compiledRule
	hasMultiline   bool
	replacement    string
	maxWindowLines int
	maxWindowBytes int
}

// NewConfig validates the given rules and window bounds before any log data is
// processed and returns a Config ready for use.
//
// Validation errors name the offending rule (by Name or index) and repeat the
// regexp compiler's message; they never include log content or caller-supplied
// sample data, only the pattern source the operator configured themselves.
func NewConfig(rules []Rule, opts ...ConfigOption) (*Config, error) {
	cfg := &Config{
		replacement:    DefaultReplacement,
		maxWindowLines: DefaultMaxWindowLines,
		maxWindowBytes: DefaultMaxWindowBytes,
	}

	for _, opt := range opts {
		opt(cfg)
	}

	if cfg.maxWindowLines <= 0 {
		return nil, fmt.Errorf("redaction: max window lines must be positive, got %d", cfg.maxWindowLines)
	}
	if cfg.maxWindowBytes <= 0 {
		return nil, fmt.Errorf("redaction: max window bytes must be positive, got %d", cfg.maxWindowBytes)
	}
	if cfg.maxWindowBytes > maxAllowedWindowBytes {
		return nil, fmt.Errorf("redaction: max window bytes %d exceeds allowed maximum %d", cfg.maxWindowBytes, maxAllowedWindowBytes)
	}
	if cfg.replacement == "" {
		return nil, fmt.Errorf("redaction: replacement marker must not be empty")
	}

	namedRules := make(map[string]struct{}, len(rules))
	cfg.rules = make([]compiledRule, 0, len(rules))

	for i, rule := range rules {
		label := ruleLabel(rule, i)

		if rule.Pattern == "" {
			return nil, fmt.Errorf("redaction: rule %s: empty pattern", label)
		}
		if rule.Name != "" {
			if _, exists := namedRules[rule.Name]; exists {
				return nil, fmt.Errorf("redaction: duplicate rule name %q", rule.Name)
			}
			namedRules[rule.Name] = struct{}{}
		}

		compiled := compiledRule{
			name:         rule.Name,
			multiline:    rule.Multiline,
			replacement:  cfg.replacement,
			captureGroup: rule.captureGroup,
		}
		if rule.Replacement != "" {
			compiled.replacement = rule.Replacement
		}

		switch rule.Kind {
		case KindRegexp:
			re, err := regexp.Compile(rule.Pattern)
			if err != nil {
				return nil, fmt.Errorf("redaction: rule %s: compile regexp: %w", label, err)
			}
			compiled.re = re
		case KindLiteral:
			if rule.Multiline {
				return nil, fmt.Errorf("redaction: rule %s: multiline literal rules are not supported, use a regexp", label)
			}
			// Anchor via quoting so every byte of the pattern is matched as
			// fixed text.
			re, err := regexp.Compile(regexp.QuoteMeta(rule.Pattern))
			if err != nil {
				return nil, fmt.Errorf("redaction: rule %s: compile literal: %w", label, err)
			}
			compiled.re = re
		default:
			return nil, fmt.Errorf("redaction: rule %s: unknown rule kind %d", label, rule.Kind)
		}

		// Idempotency guard: a rule that matches its own marker would replace
		// already redacted output again on a second pass. Reject it up front
		// so repeated processing provably stays stable.
		if compiled.re.MatchString(compiled.replacement) {
			return nil, fmt.Errorf("redaction: rule %s: pattern matches its own replacement marker %q, repeated redaction would not be stable", label, compiled.replacement)
		}

		cfg.rules = append(cfg.rules, compiled)
		if rule.Multiline {
			cfg.hasMultiline = true
		}
	}

	return cfg, nil
}

// ConfigOption tunes validated Config defaults.
type ConfigOption func(*Config)

// WithReplacement sets the marker used by rules that do not define their own
// replacement.
func WithReplacement(marker string) ConfigOption {
	return func(c *Config) { c.replacement = marker }
}

// WithMaxWindowLines overrides DefaultMaxWindowLines.
func WithMaxWindowLines(n int) ConfigOption {
	return func(c *Config) { c.maxWindowLines = n }
}

// WithMaxWindowBytes overrides DefaultMaxWindowBytes.
func WithMaxWindowBytes(n int) ConfigOption {
	return func(c *Config) { c.maxWindowBytes = n }
}

// KeyValueRule returns a regexp rule matching assignments of the given key
// (e.g. "token", "password") followed by an optional separator and a value,
// masking the value only while keeping the key visible.
//
// The value terminates at whitespace, a quote, an ampersand or a semicolon,
// which covers the common "token=abc123", "password: s3cr3t" and
// "TOKEN=abc&other=1" shapes. Matching is case-insensitive on the key and
// requires a word boundary before it, so "mytoken=x" is not touched. It is a
// convenience wrapper around Rule, not secret auto-detection: only the named
// keys are matched.
func KeyValueRule(key string) (Rule, error) {
	if key == "" {
		return Rule{}, fmt.Errorf("redaction: key-value rule requires a non-empty key")
	}

	// Group 1 captures the key plus separator verbatim and is re-emitted in
	// front of the marker, so only the value disappears.
	pattern := `(?i)(\b` + regexp.QuoteMeta(key) + `\s*[:=]\s*)[^\s"';,&]+`
	if _, err := regexp.Compile(pattern); err != nil {
		return Rule{}, fmt.Errorf("redaction: build key-value rule for %q: %w", key, err)
	}

	return Rule{
		Name:      "key-value:" + key,
		Kind:      KindRegexp,
		Pattern:   pattern,
		Multiline: false,
		// captureGroup is consumed by the engine to keep group 1 and replace
		// group 2 only.
		captureGroup: 1,
	}, nil
}

type compiledRule struct {
	name         string
	re           *regexp.Regexp
	multiline    bool
	replacement  string
	captureGroup int
}

func ruleLabel(rule Rule, index int) string {
	if rule.Name != "" {
		return fmt.Sprintf("%q", rule.Name)
	}
	return fmt.Sprintf("#%d", index)
}
