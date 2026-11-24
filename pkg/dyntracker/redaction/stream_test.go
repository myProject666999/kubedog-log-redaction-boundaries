package redaction

import (
	"fmt"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/werf/kubedog/pkg/log"
)

// feedAll writes the whole stream in one Write and returns the final lines
// (including Flush for a newline-less tail).
func feedAll(t *testing.T, sr *StreamRedactor, data []byte) []log.LogLine {
	t.Helper()
	out := sr.Write(data)
	out = append(out, sr.Flush()...)
	return out
}

// feedSplits writes data in chunks delimited at every possible byte boundary
// (including 1-byte writes) and returns the final lines. Every split must
// produce exactly the same output as a single write.
func feedSplits(t *testing.T, cfg *Config, data []byte, splitAt int) []log.LogLine {
	t.Helper()
	sr := NewStreamRedactor(cfg)
	var out []log.LogLine
	for start := 0; start < len(data); start += splitAt {
		end := start + splitAt
		if end > len(data) {
			end = len(data)
		}
		out = append(out, sr.Write(data[start:end])...)
	}
	out = append(out, sr.Flush()...)
	return out
}

func TestStream_ChunkBoundaryInvariance(t *testing.T) {
	cfg, err := NewConfig([]Rule{
		{Name: "token", Kind: KindRegexp, Pattern: `token=\S+`},
		{Name: "literal", Kind: KindLiteral, Pattern: "supersecret"},
		{Name: "ml", Kind: KindRegexp, Pattern: `BEGIN[\s\S]*?END`, Multiline: true},
	})
	if err != nil {
		t.Fatal(err)
	}

	stream := []byte(strings.Join([]string{
		"2026-11-25T10:00:00Z login token=abc123 ok",
		"2026-11-25T10:00:01Z a supersecret value",
		"2026-11-25T10:00:02Z BEGIN",
		"2026-11-25T10:00:03Z cross line secret body",
		"2026-11-25T10:00:04Z END done",
		"2026-11-25T10:00:05Z 日本語 token=zzz trailing",
	}, "\n") + "\n")

	baseline := feedAll(t, NewStreamRedactor(cfg), stream)

	for split := 1; split <= len(stream); split++ {
		got := feedSplits(t, cfg, stream, split)
		if !equalLogLines(got, baseline) {
			t.Fatalf("split size %d changes output:\n got=%q\nwant=%q", split, dumpLines(got), dumpLines(baseline))
		}
	}

	// Content assertions on the baseline.
	for _, line := range baseline {
		if strings.Contains(line.Message, "abc123") ||
			strings.Contains(line.Message, "supersecret") ||
			strings.Contains(line.Message, "zzz") ||
			strings.Contains(line.Message, "cross line secret body") {
			t.Fatalf("sensitive value leaked: %q", dumpLines(baseline))
		}
	}
}

func TestStream_TimestampNeverMatched(t *testing.T) {
	// A pattern that would match inside an RFC3339 timestamp must still only
	// see the message body.
	cfg, err := NewConfig([]Rule{{Kind: KindRegexp, Pattern: `[0-9]{2}:[0-9]{2}:[0-9]{2}`}})
	if err != nil {
		t.Fatal(err)
	}

	data := []byte("2026-11-25T10:00:00Z message 12:34:56 body\n")
	got := feedAll(t, NewStreamRedactor(cfg), data)

	if len(got) != 1 {
		t.Fatalf("want 1 line, got %q", dumpLines(got))
	}
	if got[0].Timestamp != "2026-11-25T10:00:00Z" {
		t.Fatalf("timestamp modified: %q", got[0].Timestamp)
	}
	if got[0].Message != "message "+DefaultReplacement+" body" {
		t.Fatalf("body redaction wrong: %q", got[0].Message)
	}
}

func TestStream_TimestampOnlyLineProducesNoOutput(t *testing.T) {
	cfg, err := NewConfig([]Rule{{Kind: KindRegexp, Pattern: `body-\d+`}})
	if err != nil {
		t.Fatal(err)
	}

	// No space separator at all -> dropped, exactly like the pod tracker.
	got := feedAll(t, NewStreamRedactor(cfg), []byte("2026-11-25T10:00:00Z\n2026-11-25T10:00:01Z body-1\n"))
	if len(got) != 1 || got[0].Message != DefaultReplacement || got[0].Timestamp != "2026-11-25T10:00:01Z" {
		t.Fatalf("timestamp-only handling wrong: %q", dumpLines(got))
	}
}

func TestStream_EmptyInputs(t *testing.T) {
	sr := NewStreamRedactor(nil)
	if out := sr.Write(nil); len(out) != 0 {
		t.Fatalf("nil write produced output: %q", dumpLines(out))
	}
	if out := sr.Write([]byte{}); len(out) != 0 {
		t.Fatalf("empty write produced output: %q", dumpLines(out))
	}
	if out := sr.Flush(); len(out) != 0 {
		t.Fatalf("empty flush produced output: %q", dumpLines(out))
	}
}

func TestStream_FinalSegmentWithoutNewline(t *testing.T) {
	cfg, err := NewConfig([]Rule{{Kind: KindRegexp, Pattern: `token=\S+`}})
	if err != nil {
		t.Fatal(err)
	}

	// Last segment has no newline; Flush must still emit it, redacted.
	data := []byte("2026-11-25T10:00:00Z first\n2026-11-25T10:00:01Z token=tail-secret")
	got := feedAll(t, NewStreamRedactor(cfg), data)

	if len(got) != 2 {
		t.Fatalf("want 2 lines, got %q", dumpLines(got))
	}
	if got[1].Message != DefaultReplacement || got[1].Timestamp != "2026-11-25T10:00:01Z" {
		t.Fatalf("tail segment wrong: %q", dumpLines(got))
	}
}

func TestStream_MultibyteRuneSplitAcrossChunks(t *testing.T) {
	cfg, err := NewConfig([]Rule{{Kind: KindLiteral, Pattern: "秘密"}})
	if err != nil {
		t.Fatal(err)
	}

	// "秘" is 3 bytes in UTF-8. Split inside the rune repeatedly.
	data := []byte("2026-11-25T10:00:00Z prefix 秘密 middle 🍣 suffix\n")
	baseline := feedAll(t, NewStreamRedactor(cfg), data)

	for split := 1; split <= len(data); split++ {
		got := feedSplits(t, cfg, data, split)
		if !equalLogLines(got, baseline) {
			t.Fatalf("multibyte split at %d differs:\n got=%q\nwant=%q", split, dumpLines(got), dumpLines(baseline))
		}
	}

	want := "prefix " + DefaultReplacement + " middle 🍣 suffix"
	if baseline[0].Message != want {
		t.Fatalf("multibyte masking wrong: got %q want %q", baseline[0].Message, want)
	}
}

func TestStream_InvalidUTF8IsDeterministic(t *testing.T) {
	cfg, err := NewConfig([]Rule{{Kind: KindLiteral, Pattern: "token"}})
	if err != nil {
		t.Fatal(err)
	}

	// 0xff is never valid UTF-8; it must become RuneError identically for
	// every chunking, never panic or get silently dropped.
	data := []byte("2026-11-25T10:00:00Z bad \xff token end\n")
	baseline := feedAll(t, NewStreamRedactor(cfg), data)

	for split := 1; split <= len(data); split++ {
		got := feedSplits(t, cfg, data, split)
		if !equalLogLines(got, baseline) {
			t.Fatalf("invalid utf8 split at %d differs: %q vs %q", split, dumpLines(got), dumpLines(baseline))
		}
	}

	if !strings.ContainsRune(baseline[0].Message, utf8.RuneError) {
		t.Fatalf("expected RuneError in %q", baseline[0].Message)
	}
	if strings.Contains(baseline[0].Message, "token") {
		t.Fatalf("rule did not apply around invalid utf8: %q", baseline[0].Message)
	}
}

func TestStream_LongLineTruncationRedactsBeforeTruncating(t *testing.T) {
	cfg, err := NewConfig([]Rule{{Kind: KindRegexp, Pattern: `SECRET-\d+`}})
	if err != nil {
		t.Fatal(err)
	}

	// Build a line longer than the limit, with an identified secret inside
	// the retained prefix and another inside the discarded tail.
	head := "2026-11-25T10:00:00Z " + "SECRET-1 " + strings.Repeat("a", ContainerLogLineLengthLimit)
	tail := " SECRET-2\n"
	data := []byte(head + tail)

	got := feedAll(t, NewStreamRedactor(cfg), data)
	if len(got) != 1 {
		t.Fatalf("want single truncated line, got %d", len(got))
	}
	line := got[0].Message
	if strings.Contains(line, "SECRET-1") || strings.Contains(line, "SECRET-2") {
		t.Fatalf("secret survived truncation: %q", line)
	}
	if !strings.Contains(line, "truncated by kubedog") {
		t.Fatalf("truncation marker missing: %q", line)
	}
	if len(line) > ContainerLogLineLengthLimit+128 {
		t.Fatalf("truncated line still too long: %d bytes", len(line))
	}

	// Chunk invariance for the oversized line too.
	for _, split := range []int{1, 7, 4096, 65536} {
		chunked := feedSplits(t, cfg, data, split)
		if !equalLogLines(chunked, got) {
			t.Fatalf("truncation split at %d differs", split)
		}
	}
}

func TestStream_PassThroughWithoutConfig(t *testing.T) {
	data := []byte("2026-11-25T10:00:00Z token=plain value 日本語\n2026-11-25T10:00:01Z next\n")
	got := feedAll(t, NewStreamRedactor(nil), data)

	want := []log.LogLine{
		{Timestamp: "2026-11-25T10:00:00Z", Message: "token=plain value 日本語"},
		{Timestamp: "2026-11-25T10:00:01Z", Message: "next"},
	}
	if !equalLogLines(got, want) {
		t.Fatalf("pass-through mismatch:\n got=%q\nwant=%q", dumpLines(got), dumpLines(want))
	}
}

func TestStream_ResetIsolatesSources(t *testing.T) {
	cfg, err := NewConfig([]Rule{
		{Kind: KindRegexp, Pattern: `BEGIN[\s\S]*?END`, Multiline: true},
		{Kind: KindRegexp, Pattern: `token=\S+`},
	})
	if err != nil {
		t.Fatal(err)
	}

	sr := NewStreamRedactor(cfg)
	// First source leaves an unterminated multiline window and a split rune
	// fragment in lineBuf.
	sr.Write([]byte("2026-11-25T10:00:00Z BEGIN unterminated"))
	sr.Reset()

	got := feedAll(t, sr, []byte("2026-11-25T11:00:00Z token=fresh\n"))
	if len(got) != 1 || got[0].Message != DefaultReplacement || got[0].Timestamp != "2026-11-25T11:00:00Z" {
		t.Fatalf("reset failed to isolate sources: %q", dumpLines(got))
	}
}

func TestStream_TimestampsFollowWindowEviction(t *testing.T) {
	cfg, err := NewConfig(
		[]Rule{{Kind: KindRegexp, Pattern: `BEGIN[\s\S]*?END`, Multiline: true}},
		WithMaxWindowLines(3),
	)
	if err != nil {
		t.Fatal(err)
	}

	data := []byte(strings.Join([]string{
		"2026-01-01T00:00:01Z BEGIN one",
		"2026-01-01T00:00:02Z two",
		"2026-01-01T00:00:03Z three",
		"2026-01-01T00:00:04Z four",
	}, "\n") + "\n")

	got := feedAll(t, NewStreamRedactor(cfg), data)
	gotTimestamps := make([]string, len(got))
	for i, line := range got {
		gotTimestamps[i] = line.Timestamp
	}
	wantTimestamps := []string{
		"2026-01-01T00:00:01Z",
		"2026-01-01T00:00:02Z",
		"2026-01-01T00:00:03Z",
		"2026-01-01T00:00:04Z",
	}
	if !equalStrings(gotTimestamps, wantTimestamps) {
		t.Fatalf("evicted lines lost timestamps: got %q want %q", gotTimestamps, wantTimestamps)
	}
}

func equalLogLines(a, b []log.LogLine) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i].Timestamp != b[i].Timestamp || a[i].Message != b[i].Message {
			return false
		}
	}
	return true
}

func dumpLines(lines []log.LogLine) string {
	parts := make([]string, len(lines))
	for i, line := range lines {
		parts[i] = fmt.Sprintf("{%s %q}", line.Timestamp, line.Message)
	}
	return "[" + strings.Join(parts, ", ") + "]"
}
