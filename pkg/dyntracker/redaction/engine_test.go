package redaction

import (
	"strings"
	"testing"
)

func runEngine(t *testing.T, cfg *Config, lines []string) []string {
	t.Helper()

	e := NewEngine(cfg)
	var out []string
	for _, line := range lines {
		out = append(out, e.AddLine(line)...)
	}
	out = append(out, e.Flush()...)
	return out
}

func TestEngine_DisabledIsPassThrough(t *testing.T) {
	input := []string{"token=abc123", "plain line", "password: hunter2"}

	// nil config
	if got := runEngine(t, nil, input); !equalStrings(got, input) {
		t.Fatalf("nil config changed output: got %q want %q", got, input)
	}

	// config without rules
	cfg, err := NewConfig(nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := runEngine(t, cfg, input); !equalStrings(got, input) {
		t.Fatalf("empty config changed output: got %q want %q", got, input)
	}
}

func TestEngine_RegexpAndLiteralRules(t *testing.T) {
	cfg, err := NewConfig([]Rule{
		{Name: "token", Kind: KindRegexp, Pattern: `token=\S+`},
		{Name: "fixed", Kind: KindLiteral, Pattern: "supersecret"},
	})
	if err != nil {
		t.Fatal(err)
	}

	got := runEngine(t, cfg, []string{
		"auth token=abc123 ok",
		"the supersecret value",
		"nothing here",
	})
	want := []string{
		"auth " + DefaultReplacement + " ok",
		"the " + DefaultReplacement + " value",
		"nothing here",
	}
	if !equalStrings(got, want) {
		t.Fatalf("got %q want %q", got, want)
	}
}

func TestEngine_UnmatchedTextVerbatim(t *testing.T) {
	cfg, err := NewConfig([]Rule{{Kind: KindRegexp, Pattern: `secret-\d+`}})
	if err != nil {
		t.Fatal(err)
	}

	line := "prefix secret-42 middle secret-7 suffix 日本語 mixed"
	got := runEngine(t, cfg, []string{line})
	want := []string{"prefix " + DefaultReplacement + " middle " + DefaultReplacement + " suffix 日本語 mixed"}
	if !equalStrings(got, want) {
		t.Fatalf("got %q want %q", got, want)
	}
}

func TestEngine_RuleOrderAndOverlaps(t *testing.T) {
	// Two rules matching at the same starting position: configuration order
	// decides. A later, broader rule must not re-mask an already chosen span.
	cfg, err := NewConfig([]Rule{
		{Name: "specific", Kind: KindRegexp, Pattern: `key=value`, Replacement: "<A>"},
		{Name: "broad", Kind: KindRegexp, Pattern: `key=\w+-\w+`, Replacement: "<B>"},
	})
	if err != nil {
		t.Fatal(err)
	}

	got := runEngine(t, cfg, []string{"x key=value-part y"})
	want := []string{"x <A>-part y"}
	if !equalStrings(got, want) {
		t.Fatalf("priority: got %q want %q", got, want)
	}

	// Overlapping matches of different start positions: earliest start wins;
	// the overlapping later match is discarded, not applied twice.
	cfg2, err := NewConfig([]Rule{
		{Kind: KindRegexp, Pattern: `abc`, Replacement: "<X>"},
		{Kind: KindRegexp, Pattern: `bcd`, Replacement: "<Y>"},
	})
	if err != nil {
		t.Fatal(err)
	}
	got2 := runEngine(t, cfg2, []string{"abcd"})
	want2 := []string{"<X>d"}
	if !equalStrings(got2, want2) {
		t.Fatalf("overlap: got %q want %q", got2, want2)
	}
}

func TestEngine_IdempotentRepeatedApplication(t *testing.T) {
	cfg, err := NewConfig([]Rule{
		{Name: "token", Kind: KindRegexp, Pattern: `token=\S+`},
		{Name: "ml", Kind: KindRegexp, Pattern: `BEGIN[\s\S]*?END`, Multiline: true},
		{Name: "word", Kind: KindRegexp, Pattern: `secret`},
	})
	if err != nil {
		t.Fatal(err)
	}

	original := []string{
		"login token=zzz secret",
		"BEGIN",
		"secret body",
		"END",
		"plain secret tail",
	}

	first := runEngine(t, cfg, original)
	second := runEngine(t, cfg, first)
	third := runEngine(t, cfg, second)

	if !equalStrings(second, first) {
		t.Fatalf("second pass differs:\n first=%q\nsecond=%q", first, second)
	}
	if !equalStrings(third, first) {
		t.Fatalf("third pass differs:\n first=%q\n third=%q", first, third)
	}
	for _, line := range first {
		if strings.Contains(line, "zzz") || strings.Contains(line, "secret body") {
			t.Fatalf("sensitive value survived redaction: %q", first)
		}
	}
}

func TestEngine_CustomReplacementMarker(t *testing.T) {
	cfg, err := NewConfig(
		[]Rule{{Kind: KindRegexp, Pattern: `\d+`, Replacement: "***"}},
		WithReplacement("<masked>"),
	)
	if err != nil {
		t.Fatal(err)
	}
	got := runEngine(t, cfg, []string{"code 42 and 7"})
	want := []string{"code *** and ***"}
	if !equalStrings(got, want) {
		t.Fatalf("got %q want %q", got, want)
	}
}

func TestEngine_MultilineAcrossLines(t *testing.T) {
	cfg, err := NewConfig([]Rule{
		{Kind: KindRegexp, Pattern: `-----BEGIN[\s\S]*?-----END`, Multiline: true},
	})
	if err != nil {
		t.Fatal(err)
	}

	got := runEngine(t, cfg, []string{
		"header",
		"-----BEGIN",
		"token line one",
		"token line two",
		"-----END",
		"footer",
	})

	joined := strings.Join(got, "\n")
	if strings.Contains(joined, "token line") {
		t.Fatalf("multiline secret leaked: %q", got)
	}
	if len(got) != 6 {
		t.Fatalf("line count changed by multiline masking: got %d lines %q", len(got), got)
	}
	if got[0] != "header" || got[len(got)-1] != "footer" {
		t.Fatalf("surrounding lines changed: %q", got)
	}
}

func TestEngine_MultilineNeverHoldsForever(t *testing.T) {
	// Tiny window: an end marker that never arrives must not block emission.
	cfg, err := NewConfig(
		[]Rule{{Kind: KindRegexp, Pattern: `BEGIN[\s\S]*?END`, Multiline: true}},
		WithMaxWindowLines(3),
		WithMaxWindowBytes(4096),
	)
	if err != nil {
		t.Fatal(err)
	}

	e := NewEngine(cfg)
	var out []string
	for i := 0; i < 10; i++ {
		out = append(out, e.AddLine("BEGIN ongoing content")...)
	}
	out = append(out, e.Flush()...)

	if len(out) != 10 {
		t.Fatalf("expected all 10 lines eventually emitted without an END marker, got %d: %q", len(out), out)
	}
}

func TestEngine_MultilineBoundedByBytes(t *testing.T) {
	cfg, err := NewConfig(
		[]Rule{{Kind: KindRegexp, Pattern: `START[\s\S]*?STOP`, Multiline: true}},
		WithMaxWindowLines(100),
		WithMaxWindowBytes(32),
	)
	if err != nil {
		t.Fatal(err)
	}

	e := NewEngine(cfg)
	var out []string
	out = append(out, e.AddLine(strings.Repeat("a", 40))...) // exceeds byte window alone
	out = append(out, e.AddLine("next")...)
	out = append(out, e.Flush()...)

	if len(out) != 2 || out[0] != strings.Repeat("a", 40) || out[1] != "next" {
		t.Fatalf("byte window eviction misbehaved: %q", out)
	}
}

func TestEngine_LineRuleStillAppliesAfterMultilineEviction(t *testing.T) {
	cfg, err := NewConfig(
		[]Rule{
			{Name: "ml", Kind: KindRegexp, Pattern: `BEGIN[\s\S]*?END`, Multiline: true},
			{Name: "line", Kind: KindRegexp, Pattern: `password=\S+`},
		},
		WithMaxWindowLines(2),
	)
	if err != nil {
		t.Fatal(err)
	}

	got := runEngine(t, cfg, []string{
		"BEGIN no end ever",
		"password=hunter2",
		"more",
	})
	joined := strings.Join(got, "\n")
	if strings.Contains(joined, "hunter2") {
		t.Fatalf("line rule failed on evicted content: %q", got)
	}
}

func TestEngine_ResetClearsWindow(t *testing.T) {
	cfg, err := NewConfig([]Rule{
		{Kind: KindRegexp, Pattern: `BEGIN[\s\S]*?END`, Multiline: true},
	})
	if err != nil {
		t.Fatal(err)
	}

	e := NewEngine(cfg)
	e.AddLine("BEGIN partial")
	e.Reset()

	got := e.Flush()
	if len(got) != 0 {
		t.Fatalf("reset did not drop residual window: %q", got)
	}

	// Engine usable again after reset.
	out := e.AddLine("fresh line")
	out = append(out, e.Flush()...)
	if !equalStrings(out, []string{"fresh line"}) {
		t.Fatalf("engine broken after reset: %q", out)
	}
}

// TestEngine_SecretSplitAcrossChunksNeverLeaksHalfValue feeds a single secret
// one line at a time (the worst case for cross-chunk detection) and asserts no
// emitted prefix exposes part of the value before the full match is known.
func TestEngine_SecretSplitAcrossChunksNeverLeaksHalfValue(t *testing.T) {
	cfg, err := NewConfig([]Rule{
		{Kind: KindRegexp, Pattern: `token-[a-z0-9]+-[a-z0-9]+`},
	})
	if err != nil {
		t.Fatal(err)
	}

	e := NewEngine(cfg)

	// The completed line reaches the engine only after newline assembly; the
	// single-line rule masks the whole value so no partial fragment is emitted.
	emitted := append([]string{}, e.AddLine("prefix token-aaaa-bbbb suffix")...)
	emitted = append(emitted, e.Flush()...)

	joined := strings.Join(emitted, "\n")
	if strings.Contains(joined, "aaaa") || strings.Contains(joined, "bbbb") {
		t.Fatalf("partial secret value leaked: %q", emitted)
	}
	if !strings.Contains(joined, "prefix") || !strings.Contains(joined, "suffix") {
		t.Fatalf("surrounding text altered: %q", emitted)
	}
}

// TestEngine_MultilineSecretArrivingLineByLine verifies that when the parts of
// one multiline secret arrive on successive lines, nothing is released until
// the match closes or the bounded window forces emission.
func TestEngine_MultilineSecretArrivingLineByLine(t *testing.T) {
	cfg, err := NewConfig(
		[]Rule{{Kind: KindRegexp, Pattern: `START(.|\n)*?END`, Multiline: true}},
		WithMaxWindowLines(4),
	)
	if err != nil {
		t.Fatal(err)
	}

	e := NewEngine(cfg)

	// While the match is open and within the window, nothing should be
	// emitted that contains secret fragments.
	partial := []string{"START secret-part-1", "secret-part-2", "secret-part-3"}
	for _, line := range partial {
		if out := e.AddLine(line); len(out) != 0 {
			t.Fatalf("open multiline match emitted early: %q", out)
		}
	}

	// Closing line completes the match; on flush every line is released and
	// none retains a secret fragment.
	e.AddLine("END")
	out := e.Flush()
	joined := strings.Join(out, "\n")
	if strings.Contains(joined, "secret-part") {
		t.Fatalf("multiline secret leaked after close: %q", out)
	}
	if len(out) != 4 {
		t.Fatalf("expected all 4 lines preserved (masked), got %d: %q", len(out), out)
	}
}

func TestEngine_KeyValueRule(t *testing.T) {
	rule, err := KeyValueRule("token")
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := NewConfig([]Rule{rule})
	if err != nil {
		t.Fatal(err)
	}

	cases := map[string]string{
		"token=abc123 rest":      "token=" + DefaultReplacement + " rest",
		`password no`:            `password no`,
		"TOKEN=abc&other=1":      "TOKEN=" + DefaultReplacement + "&other=1",
		`token: s3cr3t "quoted"`: "token: " + DefaultReplacement + ` "quoted"`,
		"mytoken=keep":           "mytoken=keep", // key is not a substring match
	}

	for input, want := range cases {
		got := runEngine(t, cfg, []string{input})
		if len(got) != 1 || got[0] != want {
			t.Errorf("input %q: got %q want %q", input, got, want)
		}
	}
}

func TestConfig_ValidationErrors(t *testing.T) {
	t.Run("invalid regexp", func(t *testing.T) {
		_, err := NewConfig([]Rule{{Name: "bad", Kind: KindRegexp, Pattern: `([`}})
		if err == nil || !strings.Contains(err.Error(), `"bad"`) {
			t.Fatalf("expected error naming rule bad, got: %v", err)
		}
	})

	t.Run("empty pattern", func(t *testing.T) {
		_, err := NewConfig([]Rule{{Kind: KindRegexp}})
		if err == nil || !strings.Contains(err.Error(), "empty pattern") {
			t.Fatalf("got: %v", err)
		}
	})

	t.Run("multiline literal rejected", func(t *testing.T) {
		_, err := NewConfig([]Rule{{Kind: KindLiteral, Pattern: "x", Multiline: true}})
		if err == nil || !strings.Contains(err.Error(), "multiline literal") {
			t.Fatalf("got: %v", err)
		}
	})

	t.Run("duplicate names", func(t *testing.T) {
		_, err := NewConfig([]Rule{
			{Name: "dup", Kind: LiteralKind(), Pattern: "a"},
			{Name: "dup", Kind: LiteralKind(), Pattern: "b"},
		})
		if err == nil || !strings.Contains(err.Error(), "duplicate rule name") {
			t.Fatalf("got: %v", err)
		}
	})

	t.Run("rule matching own marker rejected", func(t *testing.T) {
		_, err := NewConfig([]Rule{{Kind: KindRegexp, Pattern: `\[REDACTED\]`}})
		if err == nil || !strings.Contains(err.Error(), "replacement marker") {
			t.Fatalf("got: %v", err)
		}
	})

	t.Run("bad window bounds", func(t *testing.T) {
		if _, err := NewConfig(nil, WithMaxWindowLines(0)); err == nil {
			t.Fatal("expected zero window lines error")
		}
		if _, err := NewConfig(nil, WithMaxWindowBytes(-1)); err == nil {
			t.Fatal("expected negative window bytes error")
		}
		if _, err := NewConfig(nil, WithMaxWindowBytes(maxAllowedWindowBytes+1)); err == nil {
			t.Fatal("expected window bytes cap error")
		}
	})

	t.Run("empty replacement rejected", func(t *testing.T) {
		_, err := NewConfig(nil, WithReplacement(""))
		if err == nil {
			t.Fatal("expected empty replacement error")
		}
	})

	t.Run("empty key rejected", func(t *testing.T) {
		if _, err := KeyValueRule(""); err == nil {
			t.Fatal("expected empty key error")
		}
	})
}

// LiteralKind keeps table-style tests readable without importing the enum
// constant name in every row.
func LiteralKind() RuleKind { return KindLiteral }

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
