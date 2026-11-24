package redaction

import (
	"fmt"
	"strings"
	"unicode/utf8"

	"github.com/werf/kubedog/pkg/log"
)

// ContainerLogLineLengthLimit mirrors pkg/tracker/pod.containerLogLineLengthLimit:
// a single log line longer than this many bytes is truncated with an explicit
// marker instead of being buffered without bound.
const ContainerLogLineLengthLimit = 64 * 1024

// truncationMarkerFormat is appended to a line that hit the length limit. It
// matches the wording used by the pod tracker so a redacted stream keeps the
// same externally visible shape.
const truncationMarkerFormat = " [truncated by kubedog: line exceeded %d bytes]"

// StreamRedactor assembles raw container-log bytes (the exact byte sequence
// the Kubernetes log stream returns, RFC3339 timestamp prefixes included) into
// log lines, redacts their message bodies and emits log.LogLine values.
//
// It is the chunk-boundary-safe counterpart of Engine:
//
//   - bytes may arrive in writes of any size, including 1-byte writes and
//     writes that split a UTF-8 sequence or a timestamp; the emitted lines
//     only depend on the concatenated byte stream;
//   - a multibyte rune split across writes is decoded once complete, never as
//     replacement characters; genuinely invalid UTF-8 is replaced with
//     utf8.RuneError deterministically;
//   - the timestamp prefix (everything up to the first space) is never
//     inspected by redaction rules and is emitted unchanged; a line without a
//     space separator (timestamp only) produces no output, matching the
//     existing pod tracker behavior;
//   - lines longer than ContainerLogLineLengthLimit are truncated. Redaction
//     runs on the retained prefix before the truncation marker is appended, so
//     an identified secret can never survive inside the discarded tail.
//
// One StreamRedactor belongs to one container stream. Reset on container
// switch, Flush at stream end.
type StreamRedactor struct {
	engine *Engine

	// lineBuf accumulates the current raw line (without '\n').
	lineBuf []byte
	// truncated means the current line exceeded the length limit and the
	// excess bytes are being discarded until the next newline.
	truncated bool

	// timestamps stays 1:1 aligned with engine.window: entry i is the
	// timestamp of the i-th line currently held by the engine. Window
	// evictions pop from the head together with the emitted message.
	timestamps []string
}

// NewStreamRedactor returns a byte-stream redactor for cfg. A nil cfg yields
// a pass-through assembler (still performs the same line splitting, UTF-8
// handling and truncation, but never masks content).
func NewStreamRedactor(cfg *Config) *StreamRedactor {
	return &StreamRedactor{engine: NewEngine(cfg)}
}

// Write consumes an arbitrary byte chunk and returns the completed log lines
// it made available. The returned slice (including its strings) does not alias
// the input buffer.
func (s *StreamRedactor) Write(chunk []byte) []log.LogLine {
	out := make([]log.LogLine, 0)

	for i := 0; i < len(chunk); i++ {
		bt := chunk[i]

		if bt == '\n' {
			out = append(out, s.finishLine()...)
			continue
		}

		if s.truncated {
			continue
		}

		if len(s.lineBuf) >= ContainerLogLineLengthLimit {
			s.truncated = true
			continue
		}

		s.lineBuf = append(s.lineBuf, bt)
	}

	return out
}

// Flush handles a final segment without a trailing newline and releases every
// line still held by the bounded multiline window. Timestamps of window-held
// lines are preserved verbatim.
func (s *StreamRedactor) Flush() []log.LogLine {
	out := make([]log.LogLine, 0)

	if len(s.lineBuf) > 0 || s.truncated {
		out = append(out, s.finishLine()...)
	}

	emitted := s.engine.Flush()
	for i, message := range emitted {
		ts := ""
		if i < len(s.timestamps) {
			ts = s.timestamps[i]
		}
		out = append(out, log.LogLine{Timestamp: ts, Message: message})
	}
	s.timestamps = s.timestamps[:0]

	return out
}

// Reset drops all assembly and redaction state. Use it when the underlying
// container source changes so no residual prefix, rune fragment or multiline
// window carries across sources.
func (s *StreamRedactor) Reset() {
	s.lineBuf = s.lineBuf[:0]
	s.truncated = false
	s.timestamps = s.timestamps[:0]
	s.engine.Reset()
}

// finishLine turns the accumulated bytes into one or more redacted LogLine.
func (s *StreamRedactor) finishLine() []log.LogLine {
	raw := s.lineBuf
	s.lineBuf = s.lineBuf[:0]

	truncated := s.truncated
	s.truncated = false

	// Deterministic handling of invalid UTF-8: the rune is only interpreted
	// once a full line is assembled, so a rune split between writes was
	// reassembled here before decoding.
	line := strings.ToValidUTF8(string(raw), string(utf8.RuneError))

	if truncated {
		line += fmt.Sprintf(truncationMarkerFormat, ContainerLogLineLengthLimit)
	}

	// Split timestamp and message exactly like the pod tracker: the first
	// space separates the RFC3339 prefix. Lines without a separator carry no
	// message and are dropped as before.
	parts := strings.SplitN(line, " ", 2)
	if len(parts) != 2 {
		return nil
	}
	timestamp, message := parts[0], parts[1]

	result := s.engine.ProcessLine(message)
	emitted := result.Emitted
	evicted := result.Evicted

	// Invariant: len(timestamps) is always equal to len(engine.window), so
	// the queue head holds the timestamp of the oldest buffered line. Eviction
	// pops that many head timestamps; the fed line is itself emitted (as the
	// last element) only when Evicted < len(Emitted).
	evictedTimestamps := make([]string, 0, evicted)
	for i := 0; i < evicted && len(s.timestamps) > 0; i++ {
		evictedTimestamps = append(evictedTimestamps, s.timestamps[0])
		s.timestamps = s.timestamps[1:]
	}

	out := make([]log.LogLine, 0, len(emitted))

	// Evicted lines are older than the current line, so they are emitted
	// first with their own timestamps; the current line always comes last.
	for i := 0; i < evicted && i < len(emitted); i++ {
		ts := ""
		if i < len(evictedTimestamps) {
			ts = evictedTimestamps[i]
		}
		out = append(out, log.LogLine{Timestamp: ts, Message: emitted[i]})
	}

	if evicted < len(emitted) {
		out = append(out, log.LogLine{Timestamp: timestamp, Message: emitted[len(emitted)-1]})
	}

	// Re-establish the queue/window invariant: when the new line stayed
	// buffered (no own-line emission), remember its timestamp.
	heldAfter := s.engine.WindowSize()
	if evicted == len(emitted) {
		for len(s.timestamps) < heldAfter {
			s.timestamps = append(s.timestamps, timestamp)
		}
	}
	for len(s.timestamps) > heldAfter {
		s.timestamps = s.timestamps[:len(s.timestamps)-1]
	}

	return out
}
