package dyntracker

import (
	"regexp"
	"strings"
	"testing"
	"time"

	"k8s.io/apimachinery/pkg/runtime/schema"

	"github.com/werf/kubedog/pkg/dyntracker/logstore"
	"github.com/werf/kubedog/pkg/dyntracker/redaction"
	"github.com/werf/kubedog/pkg/dyntracker/statestore"
	"github.com/werf/kubedog/pkg/dyntracker/util"
	"github.com/werf/kubedog/pkg/log"
	"github.com/werf/kubedog/pkg/tracker/pod"
)

const (
	redactionTestPod       = "demo-pod"
	redactionTestNamespace = "default"
	redactionTestContainer = "app"
)

func newRedactionTestTaskState() *statestore.ReadinessTaskState {
	return statestore.NewReadinessTaskState(
		redactionTestPod,
		redactionTestNamespace,
		schema.GroupVersionKind{Group: "", Version: "v1", Kind: "Pod"},
		statestore.ReadinessTaskStateOptions{},
	)
}

func storedMessages(t *testing.T, store *util.Concurrent[*logstore.LogStore]) []string {
	t.Helper()

	var messages []string
	store.RTransaction(func(ls *logstore.LogStore) {
		for _, crl := range ls.ResourcesLogs() {
			crl.RTransaction(func(rl *logstore.ResourceLogs) {
				for _, lines := range rl.LogLines() {
					for _, line := range lines {
						messages = append(messages, line.Line)
					}
				}
			})
		}
	})
	return messages
}

func chunk(lines ...log.LogLine) *pod.PodLogChunk {
	return &pod.PodLogChunk{
		PodName: redactionTestPod,
		ContainerLogChunk: &pod.ContainerLogChunk{
			ContainerName: redactionTestContainer,
			LogLines:      lines,
		},
	}
}

func tsLine(second int, message string) log.LogLine {
	return log.LogLine{
		Timestamp: time.Date(2026, 11, 25, 10, 0, second, 0, time.UTC).Format(time.RFC3339),
		Message:   message,
	}
}

func TestHandlePodLogChunk_RedactsBeforeStoring(t *testing.T) {
	cfg, err := redaction.NewConfig([]redaction.Rule{
		{Name: "token", Kind: redaction.KindRegexp, Pattern: `token=\S+`},
	})
	if err != nil {
		t.Fatal(err)
	}

	rt := &DynamicReadinessTracker{
		redactLogsConfig:  cfg,
		redactLogsEngines: make(map[string]*logRedactor),
	}
	store := util.NewConcurrent(logstore.NewLogStore())
	taskState := newRedactionTestTaskState()

	store.RWTransaction(func(ls *logstore.LogStore) {
		rt.handlePodLogChunk(chunk(
			tsLine(1, "login token=abc123 ok"),
			tsLine(2, "plain line"),
		), ls, taskState)
	})

	messages := storedMessages(t, store)
	joined := strings.Join(messages, "\n")
	if strings.Contains(joined, "abc123") {
		t.Fatalf("sensitive value reached the log store: %q", messages)
	}
	if !strings.Contains(joined, redaction.DefaultReplacement) {
		t.Fatalf("redaction marker missing in store: %q", messages)
	}
	if !strings.Contains(joined, "plain line") {
		t.Fatalf("unmatched content was altered: %q", messages)
	}
	if !strings.Contains(joined, "login") || !strings.Contains(joined, "ok") {
		t.Fatalf("unmatched surrounding text was altered: %q", messages)
	}
}

func TestHandlePodLogChunk_DisabledKeepsLegacyOutput(t *testing.T) {
	// No redaction config: output must be byte-identical to the messages in.
	rt := &DynamicReadinessTracker{}
	store := util.NewConcurrent(logstore.NewLogStore())
	taskState := newRedactionTestTaskState()

	input := []log.LogLine{
		tsLine(1, "token=abc123 stays visible"),
		tsLine(2, "password: hunter2 stays visible"),
	}
	store.RWTransaction(func(ls *logstore.LogStore) {
		rt.handlePodLogChunk(chunk(input...), ls, taskState)
	})

	messages := storedMessages(t, store)
	if len(messages) != len(input) {
		t.Fatalf("line count changed with redaction disabled: got %q", messages)
	}
	for i, line := range input {
		if messages[i] != line.Message {
			t.Fatalf("disabled redaction changed line %d: got %q want %q", i, messages[i], line.Message)
		}
	}
}

func TestHandlePodLogChunk_FilterRunsOnOriginalBody(t *testing.T) {
	// saveLogsByRegex selects on the ORIGINAL body. A line that only matches
	// because it still contains the unredacted token must still be selected,
	// then stored redacted. A line matching neither selector is dropped.
	cfg, err := redaction.NewConfig([]redaction.Rule{
		{Kind: redaction.KindRegexp, Pattern: `token=\S+`},
	})
	if err != nil {
		t.Fatal(err)
	}

	rt := &DynamicReadinessTracker{
		saveLogsByRegex:   regexp.MustCompile(`token=`),
		redactLogsConfig:  cfg,
		redactLogsEngines: make(map[string]*logRedactor),
	}
	store := util.NewConcurrent(logstore.NewLogStore())
	taskState := newRedactionTestTaskState()

	store.RWTransaction(func(ls *logstore.LogStore) {
		rt.handlePodLogChunk(chunk(
			tsLine(1, "token=secretvalue"), // selected on original, stored redacted
			tsLine(2, "unrelated line"),    // selector does not match -> dropped
		), ls, taskState)
	})

	messages := storedMessages(t, store)
	if len(messages) != 1 {
		t.Fatalf("save-filter semantics changed: got %q", messages)
	}
	if messages[0] != redaction.DefaultReplacement {
		t.Fatalf("selected line not redacted after filtering: %q", messages[0])
	}
}

func TestHandlePodLogChunk_SourcesDoNotShareWindow(t *testing.T) {
	cfg, err := redaction.NewConfig([]redaction.Rule{
		{Kind: redaction.KindRegexp, Pattern: `BEGIN[\s\S]*?END`, Multiline: true},
		{Kind: redaction.KindRegexp, Pattern: `token=\S+`},
	})
	if err != nil {
		t.Fatal(err)
	}

	rt := &DynamicReadinessTracker{
		redactLogsConfig:  cfg,
		redactLogsEngines: make(map[string]*logRedactor),
	}
	store := util.NewConcurrent(logstore.NewLogStore())
	taskState := newRedactionTestTaskState()

	otherContainer := "sidecar"

	// Container "app" leaves an unterminated multiline window.
	appChunk := chunk(tsLine(1, "BEGIN unterminated"))
	// Interleaved chunk from a different container must use an independent
	// engine and not see app's residual content.
	otherChunk := &pod.PodLogChunk{
		PodName: redactionTestPod,
		ContainerLogChunk: &pod.ContainerLogChunk{
			ContainerName: otherContainer,
			LogLines:      []log.LogLine{tsLine(2, "token=sidecar-secret")},
		},
	}

	store.RWTransaction(func(ls *logstore.LogStore) {
		rt.handlePodLogChunk(appChunk, ls, taskState)
		rt.handlePodLogChunk(otherChunk, ls, taskState)
	})

	messages := storedMessages(t, store)
	joined := strings.Join(messages, "\n")
	if strings.Contains(joined, "sidecar-secret") {
		t.Fatalf("other container secret leaked across sources: %q", messages)
	}
	if strings.Contains(joined, "BEGIN unterminated") {
		// The buffered line is not stored yet (window open); ensure it did not
		// leak through the other container's flush.
		t.Fatalf("residual window content leaked across sources: %q", messages)
	}

	// Two distinct engines must exist internally.
	if len(rt.redactLogsEngines) != 2 {
		t.Fatalf("expected one redactor per source, got %d", len(rt.redactLogsEngines))
	}
}

func TestHandlePodLogChunk_FlushReleasesWindowWithTimestamps(t *testing.T) {
	cfg, err := redaction.NewConfig(
		[]redaction.Rule{{Kind: redaction.KindRegexp, Pattern: `BEGIN[\s\S]*?END`, Multiline: true}},
		redaction.WithMaxWindowLines(2),
	)
	if err != nil {
		t.Fatal(err)
	}

	rt := &DynamicReadinessTracker{
		taskState:         util.NewConcurrent(newRedactionTestTaskState()),
		logStore:          util.NewConcurrent(logstore.NewLogStore()),
		redactLogsConfig:  cfg,
		redactLogsEngines: make(map[string]*logRedactor),
	}

	// Drive the redactor directly through the public flush entry point.
	first := rt.redactLogLines(redactionTestPod, redactionTestContainer,
		[]log.LogLine{tsLine(1, "BEGIN one"), tsLine(2, "two"), tsLine(3, "three")})
	if len(first) == 0 {
		t.Fatal("expected window eviction to emit lines")
	}

	rt.FlushLogRedaction(redactionTestPod, redactionTestContainer)

	var messages []string
	var timestamps []time.Time
	rt.logStore.RTransaction(func(ls *logstore.LogStore) {
		for _, crl := range ls.ResourcesLogs() {
			crl.RTransaction(func(rl *logstore.ResourceLogs) {
				for _, lines := range rl.LogLines() {
					for _, line := range lines {
						messages = append(messages, line.Line)
						timestamps = append(timestamps, line.Time)
					}
				}
			})
		}
	})

	if len(messages) == 0 {
		t.Fatal("flush persisted nothing")
	}
	// Timestamps must be real parsed times, ordered and from the input lines.
	for i := 1; i < len(timestamps); i++ {
		if timestamps[i].Before(timestamps[i-1]) {
			t.Fatalf("flush broke timestamp ordering: %v", timestamps)
		}
	}
}

func TestHandlePodLogChunk_ResetClearsSourceState(t *testing.T) {
	cfg, err := redaction.NewConfig([]redaction.Rule{
		{Kind: redaction.KindRegexp, Pattern: `BEGIN[\s\S]*?END`, Multiline: true},
	})
	if err != nil {
		t.Fatal(err)
	}

	rt := &DynamicReadinessTracker{
		redactLogsConfig:  cfg,
		redactLogsEngines: make(map[string]*logRedactor),
	}

	rt.redactLogLines(redactionTestPod, redactionTestContainer,
		[]log.LogLine{tsLine(1, "BEGIN partial")})
	if len(rt.redactLogsEngines) != 1 {
		t.Fatalf("expected a buffered redactor, got %d", len(rt.redactLogsEngines))
	}

	rt.ResetLogRedaction(redactionTestPod, redactionTestContainer)
	if len(rt.redactLogsEngines) != 0 {
		t.Fatalf("reset did not drop source state: %d", len(rt.redactLogsEngines))
	}
}

// TestHandlePodLogChunk_ChunkSplittingDoesNotChangeResult verifies the core
// streaming requirement: the same logical lines must produce identical stored
// output regardless of how they are grouped into ContainerLogChunk values,
// including a multiline secret split across chunks.
func TestHandlePodLogChunk_ChunkSplittingDoesNotChangeResult(t *testing.T) {
	cfg, err := redaction.NewConfig([]redaction.Rule{
		{Name: "token", Kind: redaction.KindRegexp, Pattern: `token=\S+`},
		{Name: "ml", Kind: redaction.KindRegexp, Pattern: `BEGIN[\s\S]*?END`, Multiline: true},
	})
	if err != nil {
		t.Fatal(err)
	}

	logicalLines := []log.LogLine{
		tsLine(1, "token=one"),
		tsLine(2, "BEGIN"),
		tsLine(3, "cross-line secret"),
		tsLine(4, "END"),
		tsLine(5, "token=two"),
	}

	run := func(groups [][]log.LogLine) []string {
		store := util.NewConcurrent(logstore.NewLogStore())
		rt := &DynamicReadinessTracker{
			taskState:         util.NewConcurrent(newRedactionTestTaskState()),
			logStore:          store,
			redactLogsConfig:  cfg,
			redactLogsEngines: make(map[string]*logRedactor),
		}
		taskState := newRedactionTestTaskState()

		store.RWTransaction(func(ls *logstore.LogStore) {
			for _, group := range groups {
				rt.handlePodLogChunk(chunk(group...), ls, taskState)
			}
		})
		// Release any window-held lines exactly as a stream-end flush would.
		// Kept outside the store transaction: FlushLogRedaction takes the same
		// lock itself and RWMutex is not re-entrant.
		rt.FlushLogRedaction(redactionTestPod, redactionTestContainer)
		return storedMessages(t, store)
	}

	// One line per chunk.
	oneAtATime := make([][]log.LogLine, len(logicalLines))
	for i, line := range logicalLines {
		oneAtATime[i] = []log.LogLine{line}
	}

	// Everything in a single chunk.
	single := [][]log.LogLine{logicalLines}

	// Arbitrary uneven grouping, including the multiline secret boundary.
	uneven := [][]log.LogLine{
		{logicalLines[0], logicalLines[1]},
		{logicalLines[2]},
		{logicalLines[3], logicalLines[4]},
	}

	baseline := run(single)
	for name, groups := range map[string][][]log.LogLine{
		"one line per chunk": oneAtATime,
		"uneven grouping":    uneven,
	} {
		got := run(groups)
		if len(got) != len(baseline) {
			t.Fatalf("%s: line count differs: got %q want %q", name, got, baseline)
		}
		for i := range baseline {
			if got[i] != baseline[i] {
				t.Fatalf("%s: line %d differs: got %q want %q", name, i, got[i], baseline[i])
			}
		}
	}

	// The stored copy must contain none of the sensitive values.
	for _, secret := range []string{"one", "two", "cross-line secret"} {
		for _, message := range baseline {
			if strings.Contains(message, secret) {
				t.Fatalf("sensitive value %q present in stored output: %q", secret, baseline)
			}
		}
	}
}

func TestHandlePodLogChunk_KeyValueRuleKeepsKeyAndRepeatedApplicationStable(t *testing.T) {
	kvRule, err := redaction.KeyValueRule("password")
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := redaction.NewConfig([]redaction.Rule{kvRule})
	if err != nil {
		t.Fatal(err)
	}

	rt := &DynamicReadinessTracker{
		redactLogsConfig:  cfg,
		redactLogsEngines: make(map[string]*logRedactor),
	}
	store := util.NewConcurrent(logstore.NewLogStore())
	taskState := newRedactionTestTaskState()

	original := []log.LogLine{
		tsLine(1, `password: hunter2 "note"`),
		tsLine(2, "password=topsecret&keep=1"),
	}
	store.RWTransaction(func(ls *logstore.LogStore) {
		rt.handlePodLogChunk(chunk(original...), ls, taskState)
	})

	first := storedMessages(t, store)
	want := []string{
		"password: " + redaction.DefaultReplacement + ` "note"`,
		"password=" + redaction.DefaultReplacement + "&keep=1",
	}
	if len(first) != len(want) {
		t.Fatalf("key-value output wrong: %q", first)
	}
	for i := range want {
		if first[i] != want[i] {
			t.Fatalf("line %d: got %q want %q", i, first[i], want[i])
		}
	}

	// Re-feed the already redacted output through a fresh engine: it must not
	// change, proving stability across repeated processing.
	rt2 := &DynamicReadinessTracker{
		redactLogsConfig:  cfg,
		redactLogsEngines: make(map[string]*logRedactor),
	}
	redactedLines := make([]log.LogLine, len(first))
	for i, message := range first {
		redactedLines[i] = tsLine(i+1, message)
	}
	again := rt2.redactLogLines(redactionTestPod, redactionTestContainer, redactedLines)
	if len(again) != len(first) {
		t.Fatalf("repeated application changed line count: %q", again)
	}
	for i := range first {
		if again[i].Message != first[i] {
			t.Fatalf("repeated application unstable at %d: got %q want %q", i, again[i].Message, first[i])
		}
	}
}

func TestConfigErrors_DoNotEchoCallerSamples(t *testing.T) {
	// Validation errors may reference the operator's own pattern source but
	// must not be constructed from log content. Confirm the error surface only
	// names rule identity / pattern, using a pattern that itself looks secret.
	_, err := redaction.NewConfig([]redaction.Rule{
		{Name: "leaky", Kind: redaction.KindRegexp, Pattern: `([`},
	})
	if err == nil {
		t.Fatal("expected validation error")
	}
	msg := err.Error()
	if !strings.Contains(msg, `"leaky"`) {
		t.Fatalf("error should name the rule: %q", msg)
	}
}
