# Container log redaction

Kubedog's dynamic readiness tracker can mask explicitly configured sensitive
content in container logs **before** anything is written to the in-memory log
store or handed to a display consumer. This document describes what is
supported, where the boundaries are, and which defaults apply.

## Scope and non-goals

- Redaction is **opt-in**. With no configuration the log pipeline output is
  byte-identical to the unconfigured behavior.
- Rules are supplied by the caller as regular expressions or fixed text.
  Kubedog does **not** attempt to automatically recognize arbitrary secrets.
- Rules match the log **message body only**. The RFC3339 timestamp prefix and
  the pod/container source identifiers are never matched or modified.
- Redaction **replaces** matched values with a marker; it never deletes a
  whole line. Unmatched text, including surrounding punctuation and
  multi-byte characters, is preserved verbatim.
- Unredacted content is never written to a spare file, a debug log or a
  persistence layer first and masked later. Masking happens in the
  `handlePodLogChunk` path after the save/ignore filters selected the lines
  and before `logstore.ResourceLogs.AddLogLine`.

## Configuring rules

Build a validated `redaction.Config` before tracking starts:

```go
cfg, err := redaction.NewConfig(
    []redaction.Rule{
        {Name: "token", Kind: redaction.KindRegexp, Pattern: `token=\S+`},
        {Name: "fixed", Kind: redaction.KindLiteral, Pattern: "supersecret"},
        kvRule,                          // from redaction.KeyValueRule
        {Name: "stack", Kind: redaction.KindRegexp,
         Pattern: `-----BEGIN[\s\S]*?-----END`, Multiline: true},
    },
    redaction.WithReplacement("[REDACTED]"),
    redaction.WithMaxWindowLines(16),
    redaction.WithMaxWindowBytes(1<<20),
)
```

Then pass it through `DynamicReadinessTrackerOptions.RedactLogs`.

### Supported rule shapes

| Shape | Behavior |
| --- | --- |
| `KindRegexp` | Go RE2 expression applied to a line (or a bounded multiline window). |
| `KindLiteral` | Fixed text matched verbatim (the pattern is quoted internally). |
| `KeyValueRule(key)` | Masks the **value** of `key=…` / `key: …` while keeping the key; case-insensitive key, word-boundary anchored, value ends at whitespace, quote, `&` or `;`. |
| `Multiline: true` | Regexp only; may span line boundaries inside the bounded window. |

### Replacement marker

The default marker is `[REDACTED]` (`redaction.DefaultReplacement`). A rule may
declare its own replacement. A pattern that matches its own marker is rejected
at configuration time, because it would make repeated redaction unstable.

## Matching priority and overlaps

- Rules are applied in **configuration order**. At each position the first
  rule whose pattern matches wins.
- A later match that overlaps an already chosen span is discarded; spans never
  nest and a byte is replaced at most once.
- Existing replacement markers are never re-examined, so feeding redacted
  output through the engine again yields the identical result (idempotent).

## Multiline matching and the bounded window

A multiline rule (for example an exception block or a PEM-style marker) needs
to look across line boundaries. To keep memory and latency bounded the engine
only retains a finite window:

| Bound | Default | Hard cap |
| --- | --- | --- |
| `MaxWindowLines` | 16 lines | — (any positive value) |
| `MaxWindowBytes` | 1 MiB | 16 MiB |

Consequences, by design:

- Once a bound is reached the oldest line is released (with single-line rules
  applied) even if the multiline end marker never arrived. Buffering cannot
  block forever waiting for an end marker that may never come.
- A secret spanning **more** than the configured window is a documented
  detection boundary: the part forced out of the window is processed as
  ordinary lines. Choose the window to fit the largest block you expect; do
  not treat this as detection of arbitrarily long secrets.
- Multiline masking preserves the newline count inside a match, so the number
  of lines, their order and per-line timestamps never change.
- At stream end call `FlushLogRedaction(pod, container)` to release whatever
  the window still holds. The bounds guarantee correctness even without an
  explicit flush; the call only makes the final segment prompt.

## Chunk boundaries and UTF-8

The result depends only on the concatenated byte stream, never on how the
Kubernetes log stream split it into reads:

- A value split across `ContainerLogChunk` values is reassembled before rules
  run.
- A UTF-8 rune split across byte boundaries is decoded once whole; genuinely
  invalid UTF-8 becomes `utf8.RuneError` deterministically.
- A line without a trailing newline is still emitted on flush; empty writes
  and timestamp-only lines (no space separator) produce no output, matching the
  pod tracker.
- Lines longer than the 64 KiB `containerLogLineLengthLimit` are truncated with
  the existing marker. Redaction runs on the retained prefix first, so an
  identified secret cannot survive in the discarded tail.

## Source isolation and lifecycle

- Each `(pod, container)` source owns an independent redactor; residual window
  content of one container can never influence another.
- `ResetLogRedaction(pod, container)` discards a source's state on container
  switch or teardown. `FlushLogRedaction` / `ResetLogRedaction` are safe to call
  for unknown or unconfigured sources.

## Filtering versus redaction

The existing selectors run first, on the **original** message body, in their
historical order:

1. `IgnoreLogs` / per-container ignore,
2. `IgnoreLogsByRegex` (global then per-container),
3. `SaveLogsByRegex` (global then per-container),
4. **redaction**,
5. write to the log store.

So a `SaveLogsByRegex` that looks for an unredacted token still selects the
same lines as before; only the stored/displayed copy is masked. Redaction does
not change which sources are selected, line ordering, or continuation
semantics.

## Configuration errors

Everything is validated before log data is processed. Invalid regexps, empty
patterns, multiline literal rules, duplicate rule names, markers matched by
their own rule, non-positive window sizes and windows above the hard cap all
return explicit errors naming the offending rule. Error text references the
operator-supplied pattern only; it never echoes log content or sample secrets.

## What the tests do and do not prove

The test suite uses in-memory byte streams and a log-store double to assert,
for a fixed input containing known secrets:

- identical output for **every** possible byte split (1-byte writes upward);
- masking across multiline blocks, overlapping rules and repeated application;
- multibyte and invalid UTF-8 handling, oversized-line truncation, newline-less
  tails, empty messages and timestamp-only lines;
- per-source isolation, window eviction with preserved timestamps and
  configuration errors;
- that every visible output and every stored copy is free of the planted
  values, that unmatched text is byte-identical, and that disabling the feature
  matches the legacy output.

These are properties of the **configured** patterns. They are not, and must not
be read as, a guarantee that every possible secret is recognized.
