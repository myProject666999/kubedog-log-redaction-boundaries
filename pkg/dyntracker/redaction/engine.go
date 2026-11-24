package redaction

import "strings"

// Engine performs stateful, chunk-independent redaction of log message lines.
//
// One Engine instance belongs to exactly one log source (one container
// stream). Sources must never share an Engine: residual multiline window
// content of one container would otherwise leak into another container's
// output.
//
// The output of AddLine and Flush depends solely on the sequence of input
// lines, never on how the underlying byte stream was split into chunks.
type Engine struct {
	cfg *Config

	// window holds the not-yet-emitted lines together with their current
	// (possibly already partially masked) text.
	window []bufferedLine
	// windowBytes is the sum of the line payload byte lengths (newlines
	// excluded) and is compared against cfg.maxWindowBytes.
	windowBytes int
}

type bufferedLine struct {
	text string
}

// NewEngine returns a stateful redaction engine for cfg. A nil cfg produces a
// pass-through engine whose output equals its input.
func NewEngine(cfg *Config) *Engine {
	return &Engine{cfg: cfg}
}

// Enabled reports whether any rule is configured.
func (e *Engine) Enabled() bool {
	return e != nil && e.cfg != nil && len(e.cfg.rules) > 0
}

// WindowSize reports how many lines are currently held for possible multiline
// matches.
func (e *Engine) WindowSize() int {
	if e == nil {
		return 0
	}
	return len(e.window)
}

// LineResult is the outcome of feeding one line to the Engine.
type LineResult struct {
	// Emitted holds every line released by this call, oldest first. Earlier
	// elements are older lines forced out by the bounded window; when the fed
	// line itself was released it is the last element.
	Emitted []string
	// Evicted is the number of elements of Emitted that were already buffered
	// before this call (older window lines). The fed line is itself emitted
	// exactly when Evicted == len(Emitted) is false; otherwise it stayed
	// buffered and the caller must keep its timestamp queued.
	Evicted int
}

// AddLine feeds one log message line (without trailing newline) and returns
// the lines that became fully determined, in original order. With redaction
// disabled the line is returned unchanged and immediately.
//
// Prefer ProcessLine in stateful callers that must pair emitted lines with
// their original timestamps.
func (e *Engine) AddLine(line string) []string {
	return e.ProcessLine(line).Emitted
}

// ProcessLine feeds one line and reports the emitted lines together with how
// many of them were evicted from the pre-existing window. It lets callers
// keep a timestamp queue 1:1 aligned with the window without ambiguous
// inference from window size differences.
func (e *Engine) ProcessLine(line string) LineResult {
	if !e.Enabled() {
		return LineResult{Emitted: []string{line}, Evicted: 0}
	}

	// Fast path: when no rule can span lines there is nothing to buffer, so
	// each line is masked and returned immediately. This keeps the common
	// case latency-free and means an unflushed stream never withholds lines.
	if !e.cfg.hasMultiline {
		return LineResult{
			Emitted: []string{e.applySingleLineRules(line)},
			Evicted: 0,
		}
	}

	e.window = append(e.window, bufferedLine{text: line})
	e.windowBytes += len(line)

	e.applyMultilineRules()

	// The number of older lines evicted is exactly how much the window shrank
	// during evict: appending made it grow by one first, so a full window that
	// replaces an old line with the new one shrinks by one here even though
	// its final size equals the size before the call.
	postAppend := len(e.window)
	emitted := e.evict(false)
	evicted := postAppend - len(e.window)
	if evicted < 0 {
		evicted = 0
	}

	return LineResult{Emitted: emitted, Evicted: evicted}
}

// Flush emits every buffered line, applying the single-line rules to the
// remaining content. It must be called when the log source ends. Afterwards
// the Engine is empty and can keep processing a fresh stream of the same
// source; use Reset when the source identity changes.
func (e *Engine) Flush() []string {
	if !e.Enabled() {
		return nil
	}

	out := e.evict(true)
	e.window = e.window[:0]
	e.windowBytes = 0
	return out
}

// Reset discards all residual window state. It is used on container switches
// so an unterminated multiline match can never carry over to another source.
func (e *Engine) Reset() {
	e.window = e.window[:0]
	e.windowBytes = 0
}

// applyMultilineRules runs every multiline rule over the joined window text.
// Rules run in configuration order; maskSegments protects spans that an
// earlier rule (or an earlier call) already replaced, so repeated processing
// stays stable.
func (e *Engine) applyMultilineRules() {
	for _, rule := range e.cfg.rules {
		if !rule.multiline {
			continue
		}

		joined := e.joinWindow()
		masked := e.maskJoined(joined, rule)
		if masked == joined {
			continue
		}

		e.splitBack(masked)
	}
}

// maskJoined masks multiline matches while preserving the newline count of
// every matched span: the marker is emitted once, followed by as many literal
// '\n' bytes as the match contained. Keeping line boundaries fixed is what
// lets splitBack map masked content back onto the original lines and keeps
// per-line timestamps and ordering intact.
//
// Existing markers are skipped wholesale (marker protection) so a multiline
// rule can never match already redacted content and re-processing is stable.
func (e *Engine) maskJoined(joined string, rule compiledRule) string {
	markers := map[string]struct{}{
		replacementFor(rule, e.cfg.replacement): {},
		e.cfg.replacement:                       {},
	}

	var b strings.Builder
	rest := joined
	for {
		foundMarker, idx := earliestMarker(rest, markers)
		var segment string
		if idx < 0 {
			segment = rest
			rest = ""
		} else {
			segment = rest[:idx]
		}

		b.WriteString(maskJoinedPlain(segment, rule, e.cfg.replacement))

		if idx < 0 {
			return b.String()
		}
		b.WriteString(foundMarker)
		rest = rest[idx+len(foundMarker):]
	}
}

func maskJoinedPlain(text string, rule compiledRule, defaultReplacement string) string {
	marker := replacementFor(rule, defaultReplacement)
	matches := rule.re.FindAllStringSubmatchIndex(text, -1)
	if len(matches) == 0 {
		return text
	}

	var b strings.Builder
	last := 0
	for _, loc := range matches {
		start, end := loc[0], loc[1]
		if start < last {
			continue // overlapping an earlier match of this rule
		}
		b.WriteString(text[last:start])
		if rule.captureGroup > 0 && rule.captureGroup*2+1 < len(loc) && loc[rule.captureGroup*2] >= 0 {
			b.WriteString(text[start:loc[rule.captureGroup*2+1]])
		}
		b.WriteString(marker)
		b.WriteString(strings.Repeat("\n", strings.Count(text[start:end], "\n")))
		last = end
	}
	b.WriteString(text[last:])
	return b.String()
}

// joinWindow concatenates window lines with '\n'.
func (e *Engine) joinWindow() string {
	var b strings.Builder
	for i, line := range e.window {
		b.WriteString(line.text)
		if i < len(e.window)-1 {
			b.WriteByte('\n')
		}
	}
	return b.String()
}

// splitBack distributes a masked joined string back onto the window lines.
// Masked spans crossing a line boundary replace the covered part of every
// intersected line; the newline separators are restored, so line count and
// per-line timestamps stay intact.
func (e *Engine) splitBack(joined string) {
	segments := strings.Split(joined, "\n")
	for i := range e.window {
		e.window[i].text = segments[i]
	}
}

// evict releases lines that can no longer participate in a multiline match.
// When flush is false only lines forced out by the bounded window are
// released; a single-line window always stays buffered so a rule may still
// extend into the newest line. When flush is true everything is released at
// stream end.
func (e *Engine) evict(flush bool) []string {
	var out []string

	for len(e.window) > 0 {
		if !flush && len(e.window) > 1 &&
			(len(e.window) > e.cfg.maxWindowLines || e.windowBytes > e.cfg.maxWindowBytes) {
			// fall through and evict the oldest line
		} else if !flush {
			break
		}

		first := e.window[0]
		e.window = e.window[1:]
		e.windowBytes -= len(first.text)

		out = append(out, e.applySingleLineRules(first.text))
	}

	return out
}

func (e *Engine) applySingleLineRules(line string) string {
	single := make([]compiledRule, 0, len(e.cfg.rules))
	for _, rule := range e.cfg.rules {
		if !rule.multiline {
			single = append(single, rule)
		}
	}
	return maskSegments(line, single, e.cfg.replacement)
}

// maskSegments splits text on every replacement marker, masks only the
// segments between markers, then rejoins. This is the idempotency boundary:
// once a value became a marker it is never inspected again, regardless of the
// other rules or of how many times redaction is re-applied.
func maskSegments(text string, rules []compiledRule, defaultReplacement string) string {
	if len(rules) == 0 || text == "" {
		return text
	}

	markers := make(map[string]struct{}, len(rules)+1)
	markers[defaultReplacement] = struct{}{}
	for _, rule := range rules {
		markers[replacementFor(rule, defaultReplacement)] = struct{}{}
	}

	var b strings.Builder
	rest := text
	for {
		marker, idx := earliestMarker(rest, markers)
		if idx < 0 {
			b.WriteString(maskPlain(rest, rules, defaultReplacement))
			return b.String()
		}

		b.WriteString(maskPlain(rest[:idx], rules, defaultReplacement))
		b.WriteString(marker)
		rest = rest[idx+len(marker):]
	}
}

func earliestMarker(text string, markers map[string]struct{}) (string, int) {
	bestMarker := ""
	bestIdx := -1
	for marker := range markers {
		if idx := strings.Index(text, marker); idx >= 0 && (bestIdx == -1 || idx < bestIdx) {
			bestMarker, bestIdx = marker, idx
		}
	}
	return bestMarker, bestIdx
}

type span struct {
	start, end, ruleIndex int
	// keepEnd is the end offset of a leading capture group that must be
	// re-emitted verbatim (key-value rules keep their "key=" prefix). Zero
	// means the whole match is replaced.
	keepEnd int
}

// maskPlain applies ordered, non-overlapping regexp replacement to text that
// is known not to contain any replacement marker. At each position the first
// configured rule whose pattern matches wins; matches overlapping an already
// chosen span are discarded.
func maskPlain(text string, rules []compiledRule, defaultReplacement string) string {
	if text == "" {
		return ""
	}

	var matches []span
	for ri, rule := range rules {
		locs := rule.re.FindAllStringSubmatchIndex(text, -1)
		for _, loc := range locs {
			m := span{start: loc[0], end: loc[1], ruleIndex: ri}
			if rule.captureGroup > 0 && rule.captureGroup*2+1 < len(loc) && loc[rule.captureGroup*2] >= 0 {
				m.keepEnd = loc[rule.captureGroup*2+1]
			}
			matches = append(matches, m)
		}
	}

	if len(matches) == 0 {
		return text
	}

	sortSpans(matches)

	var b strings.Builder
	last := 0
	for _, m := range matches {
		if m.start < last {
			continue // overlaps an already chosen span
		}
		b.WriteString(text[last:m.start])
		if m.keepEnd > m.start && m.keepEnd <= m.end {
			b.WriteString(text[m.start:m.keepEnd])
		}
		b.WriteString(replacementFor(rules[m.ruleIndex], defaultReplacement))
		last = m.end
	}
	b.WriteString(text[last:])
	return b.String()
}

func sortSpans(spans []span) {
	// Insertion sort is enough: rule counts are small and this avoids pulling
	// in another package just for ordering.
	for i := 1; i < len(spans); i++ {
		for j := i; j > 0; j-- {
			if spans[j].start < spans[j-1].start ||
				(spans[j].start == spans[j-1].start && spans[j].ruleIndex < spans[j-1].ruleIndex) {
				spans[j], spans[j-1] = spans[j-1], spans[j]
			} else {
				break
			}
		}
	}
}

func replacementFor(rule compiledRule, defaultReplacement string) string {
	if rule.replacement != "" {
		return rule.replacement
	}
	return defaultReplacement
}
