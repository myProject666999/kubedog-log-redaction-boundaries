package dyntracker

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"time"

	"github.com/samber/lo"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/discovery"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	watchtools "k8s.io/client-go/tools/watch"

	"github.com/werf/kubedog/pkg/dyntracker/logstore"
	"github.com/werf/kubedog/pkg/dyntracker/redaction"
	"github.com/werf/kubedog/pkg/dyntracker/statestore"
	"github.com/werf/kubedog/pkg/dyntracker/util"
	"github.com/werf/kubedog/pkg/informer"
	"github.com/werf/kubedog/pkg/log"
	"github.com/werf/kubedog/pkg/resid"
	commontracker "github.com/werf/kubedog/pkg/tracker"
	"github.com/werf/kubedog/pkg/tracker/canary"
	"github.com/werf/kubedog/pkg/tracker/daemonset"
	"github.com/werf/kubedog/pkg/tracker/deployment"
	"github.com/werf/kubedog/pkg/tracker/generic"
	"github.com/werf/kubedog/pkg/tracker/job"
	"github.com/werf/kubedog/pkg/tracker/pod"
	"github.com/werf/kubedog/pkg/tracker/replicaset"
	"github.com/werf/kubedog/pkg/tracker/statefulset"
)

type DynamicReadinessTracker struct {
	resourceName      string
	resourceNamespace string
	resourceGVK       schema.GroupVersionKind
	resourceHumanID   string
	taskState         *util.Concurrent[*statestore.ReadinessTaskState]
	logStore          *util.Concurrent[*logstore.LogStore]
	mapper            meta.ResettableRESTMapper
	tracker           any

	timeout           time.Duration
	noActivityTimeout time.Duration

	saveLogsOnlyForContainers      []string
	saveLogsByRegex                *regexp.Regexp
	saveLogsByRegexForContainers   map[string]*regexp.Regexp
	ignoreLogs                     bool
	ignoreLogsForContainers        []string
	ignoreLogsByRegex              *regexp.Regexp
	ignoreLogsByRegexForContainers map[string]*regexp.Regexp
	redactLogsConfig               *redaction.Config
	// redactLogsEngines holds one stateful redaction source per container so
	// multiline window state is never shared between sources. The map itself
	// is only touched from the Track loop goroutine.
	redactLogsEngines map[string]*logRedactor
	saveEvents        bool
}

// logRedactor pairs a redaction Engine with a timestamp queue that stays 1:1
// aligned with the engine's window: entry i is the original Timestamp of the
// i-th line the engine currently holds. This lets window evictions and stream
// end flushes keep every emitted line's real timestamp instead of borrowing
// the timestamp of a newer line.
type logRedactor struct {
	engine     *redaction.Engine
	timestamps []string
}

func NewDynamicReadinessTracker(
	ctx context.Context,
	taskState *util.Concurrent[*statestore.ReadinessTaskState],
	logStore *util.Concurrent[*logstore.LogStore],
	informerFactory *util.Concurrent[*informer.InformerFactory],
	staticClient kubernetes.Interface,
	dynamicClient dynamic.Interface,
	discoveryClient discovery.CachedDiscoveryInterface,
	mapper meta.ResettableRESTMapper,
	opts DynamicReadinessTrackerOptions,
) (*DynamicReadinessTracker, error) {
	timeout := opts.Timeout

	var captureLogsFromTime time.Time
	if opts.CaptureLogsFromTime.IsZero() {
		captureLogsFromTime = time.Now()
	} else {
		captureLogsFromTime = opts.CaptureLogsFromTime
	}

	var noActivityTimeout time.Duration
	if opts.NoActivityTimeout != 0 {
		noActivityTimeout = opts.NoActivityTimeout
	} else {
		noActivityTimeout = 4 * time.Minute
	}

	ignoreReadinessProbeFailsByContainerName := make(map[string]time.Duration)
	if opts.IgnoreReadinessProbeFailsByContainerName != nil {
		ignoreReadinessProbeFailsByContainerName = opts.IgnoreReadinessProbeFailsByContainerName
	}

	var (
		resourceName      string
		resourceNamespace string
		resourceGVK       schema.GroupVersionKind
	)
	taskState.RTransaction(func(ts *statestore.ReadinessTaskState) {
		resourceName = ts.Name()
		resourceNamespace = ts.Namespace()
		resourceGVK = ts.GroupVersionKind()
	})

	lookupGVK := resourceGVK
	if opts.CaseInsensitiveGVKMatching {
		lookupGVK = util.LowercaseGVK(resourceGVK)
	}

	if namespaced, err := util.IsNamespaced(lookupGVK, mapper); err != nil {
		return nil, fmt.Errorf("check if namespaced: %w", err)
	} else if !namespaced {
		resourceNamespace = ""
	}

	var tracker any
	switch lookupGVK.GroupKind() {
	case schema.GroupKind{Group: "apps", Kind: "deployment"}, schema.GroupKind{Group: "extensions", Kind: "deployment"}:
		tracker = deployment.NewTracker(resourceName, resourceNamespace, staticClient, informerFactory, commontracker.Options{
			ParentContext:                            ctx,
			Timeout:                                  timeout,
			LogsFromTime:                             captureLogsFromTime,
			SaveLogsOnlyForNumberOfReplicas:          opts.SaveLogsOnlyForNumberOfReplicas,
			IgnoreLogs:                               opts.IgnoreLogs,
			IgnoreReadinessProbeFailsByContainerName: ignoreReadinessProbeFailsByContainerName,
		})
	case schema.GroupKind{Group: "apps", Kind: "daemonset"}, schema.GroupKind{Group: "extensions", Kind: "daemonset"}:
		tracker = daemonset.NewTracker(resourceName, resourceNamespace, staticClient, informerFactory, commontracker.Options{
			ParentContext:                            ctx,
			Timeout:                                  timeout,
			LogsFromTime:                             captureLogsFromTime,
			SaveLogsOnlyForNumberOfReplicas:          opts.SaveLogsOnlyForNumberOfReplicas,
			IgnoreLogs:                               opts.IgnoreLogs,
			IgnoreReadinessProbeFailsByContainerName: ignoreReadinessProbeFailsByContainerName,
		})
	case schema.GroupKind{Group: "flagger.app", Kind: "canary"}:
		tracker = canary.NewTracker(resourceName, resourceNamespace, staticClient, dynamicClient, informerFactory, commontracker.Options{
			ParentContext:                            ctx,
			Timeout:                                  timeout,
			LogsFromTime:                             captureLogsFromTime,
			IgnoreReadinessProbeFailsByContainerName: ignoreReadinessProbeFailsByContainerName,
		})
	case schema.GroupKind{Group: "apps", Kind: "statefulset"}:
		tracker = statefulset.NewTracker(resourceName, resourceNamespace, staticClient, informerFactory, commontracker.Options{
			ParentContext:                            ctx,
			Timeout:                                  timeout,
			LogsFromTime:                             captureLogsFromTime,
			SaveLogsOnlyForNumberOfReplicas:          opts.SaveLogsOnlyForNumberOfReplicas,
			IgnoreLogs:                               opts.IgnoreLogs,
			IgnoreReadinessProbeFailsByContainerName: ignoreReadinessProbeFailsByContainerName,
		})
	case schema.GroupKind{Group: "batch", Kind: "job"}:
		tracker = job.NewTracker(resourceName, resourceNamespace, staticClient, informerFactory, commontracker.Options{
			ParentContext:                            ctx,
			Timeout:                                  timeout,
			LogsFromTime:                             captureLogsFromTime,
			SaveLogsOnlyForNumberOfReplicas:          opts.SaveLogsOnlyForNumberOfReplicas,
			IgnoreLogs:                               opts.IgnoreLogs,
			IgnoreReadinessProbeFailsByContainerName: ignoreReadinessProbeFailsByContainerName,
		})
	case schema.GroupKind{Group: "", Kind: "pod"}:
		tracker = pod.NewTracker(resourceName, resourceNamespace, staticClient, informerFactory, pod.Options{
			IgnoreReadinessProbeFailsByContainerName: ignoreReadinessProbeFailsByContainerName,
			IgnoreLogs:                               opts.IgnoreLogs,
		})
	default:
		resid := resid.NewResourceID(resourceName, lookupGVK, resid.NewResourceIDOptions{
			Namespace: resourceNamespace,
		})

		tracker = generic.NewTracker(resid, dynamicClient, discoveryClient, informerFactory, mapper)
	}

	return &DynamicReadinessTracker{
		resourceName:                   resourceName,
		resourceNamespace:              resourceNamespace,
		resourceGVK:                    resourceGVK,
		resourceHumanID:                util.ResourceHumanID(resourceName, resourceNamespace, resourceGVK, mapper),
		taskState:                      taskState,
		logStore:                       logStore,
		mapper:                         mapper,
		tracker:                        tracker,
		timeout:                        timeout,
		noActivityTimeout:              noActivityTimeout,
		saveLogsOnlyForContainers:      opts.SaveLogsOnlyForContainers,
		saveLogsByRegex:                opts.SaveLogsByRegex,
		saveLogsByRegexForContainers:   opts.SaveLogsByRegexForContainers,
		ignoreLogsByRegex:              opts.IgnoreLogsByRegex,
		ignoreLogsByRegexForContainers: opts.IgnoreLogsByRegexForContainers,
		ignoreLogs:                     opts.IgnoreLogs,
		ignoreLogsForContainers:        opts.IgnoreLogsForContainers,
		redactLogsConfig:               opts.RedactLogs,
		redactLogsEngines:              make(map[string]*logRedactor),
		saveEvents:                     opts.SaveEvents,
	}, nil
}

type DynamicReadinessTrackerOptions struct {
	Timeout                                  time.Duration
	NoActivityTimeout                        time.Duration
	IgnoreReadinessProbeFailsByContainerName map[string]time.Duration
	CaptureLogsFromTime                      time.Time
	CaseInsensitiveGVKMatching               bool
	SaveLogsOnlyForNumberOfReplicas          int
	SaveLogsOnlyForContainers                []string
	SaveLogsByRegex                          *regexp.Regexp
	SaveLogsByRegexForContainers             map[string]*regexp.Regexp
	IgnoreLogs                               bool
	IgnoreLogsForContainers                  []string
	IgnoreLogsByRegex                        *regexp.Regexp
	IgnoreLogsByRegexForContainers           map[string]*regexp.Regexp
	// RedactLogs, when non-nil and non-empty of rules, masks configured
	// patterns in log message bodies after the save/ignore filters selected
	// the lines, but before anything is written to the log store. A nil
	// value keeps the historical, unredacted behavior unchanged.
	RedactLogs *redaction.Config
	SaveEvents bool
}

func (t *DynamicReadinessTracker) Track(ctx context.Context) error {
	switch tracker := t.tracker.(type) {
	case *deployment.Tracker:
		if err := t.trackDeployment(ctx, tracker); err != nil {
			return fmt.Errorf("track deployment: %w", err)
		}
	case *statefulset.Tracker:
		if err := t.trackStatefulSet(ctx, tracker); err != nil {
			return fmt.Errorf("track statefulset: %w", err)
		}
	case *daemonset.Tracker:
		if err := t.trackDaemonSet(ctx, tracker); err != nil {
			return fmt.Errorf("track daemonset: %w", err)
		}
	case *job.Tracker:
		if err := t.trackJob(ctx, tracker); err != nil {
			return fmt.Errorf("track job: %w", err)
		}
	case *canary.Tracker:
		if err := t.trackCanary(ctx, tracker); err != nil {
			return fmt.Errorf("track canary: %w", err)
		}
	case *pod.Tracker:
		if err := t.trackPod(ctx, tracker); err != nil {
			return fmt.Errorf("track standalone pod: %w", err)
		}
	case *generic.Tracker:
		if err := t.trackGeneric(ctx, tracker); err != nil {
			return fmt.Errorf("track generic: %w", err)
		}
	default:
		panic("unexpected tracker")
	}

	return nil
}

func (t *DynamicReadinessTracker) trackDeployment(ctx context.Context, tracker *deployment.Tracker) error {
	trackCtx, trackCtxCancelFn := watchtools.ContextWithOptionalTimeout(ctx, t.timeout)
	defer trackCtxCancelFn()

	trackErrCh := make(chan error, 1)
	go func() {
		trackErrCh <- tracker.Track(trackCtx)
	}()

	for {
		select {
		case err := <-trackErrCh:
			if err != nil && !errors.Is(err, commontracker.ErrStopTrack) {
				return fmt.Errorf("track resource %q: %w", t.resourceHumanID, err)
			}

			return nil
		case status := <-tracker.Added:
			var (
				abort    bool
				abortErr error
			)
			t.taskState.RWTransaction(func(ts *statestore.ReadinessTaskState) {
				t.handlePodsFromDeploymentStatus(&status, ts)
				t.handleDeploymentStatus(&status, ts)
				t.setRootResourceCreated(ts)
				abort, abortErr = t.handleTaskStateStatus(ts)
			})

			if abort {
				return abortErr
			}
		case status := <-tracker.Ready:
			var (
				abort    bool
				abortErr error
			)
			status.IsReady = true

			t.taskState.RWTransaction(func(ts *statestore.ReadinessTaskState) {
				t.handlePodsFromDeploymentStatus(&status, ts)
				t.handleDeploymentStatus(&status, ts)
				abort, abortErr = t.handleTaskStateStatus(ts)
			})

			if abort {
				return abortErr
			}
		case report := <-tracker.AddedReplicaSet:
			var (
				abort    bool
				abortErr error
			)
			t.taskState.RWTransaction(func(ts *statestore.ReadinessTaskState) {
				t.handlePodsFromDeploymentStatus(&report.DeploymentStatus, ts)
				t.handleDeploymentStatus(&report.DeploymentStatus, ts)
				abort, abortErr = t.handleTaskStateStatus(ts)
			})

			if abort {
				return abortErr
			}
		case report := <-tracker.AddedPod:
			var (
				abort    bool
				abortErr error
			)
			t.taskState.RWTransaction(func(ts *statestore.ReadinessTaskState) {
				t.handlePodsFromDeploymentStatus(&report.DeploymentStatus, ts)
				t.handlePodsFromDeploymentPodAddedReport(&report, ts)
				t.handleDeploymentStatus(&report.DeploymentStatus, ts)
				abort, abortErr = t.handleTaskStateStatus(ts)
			})

			if abort {
				return abortErr
			}
		case status := <-tracker.Failed:
			var (
				abort    bool
				abortErr error
			)
			t.taskState.RWTransaction(func(ts *statestore.ReadinessTaskState) {
				t.handlePodsFromDeploymentStatus(&status, ts)
				t.handleDeploymentStatus(&status, ts)
				abort, abortErr = t.handleTaskStateStatus(ts)
			})

			if abort {
				return abortErr
			}
		case status := <-tracker.Status:
			var (
				abort    bool
				abortErr error
			)
			t.taskState.RWTransaction(func(ts *statestore.ReadinessTaskState) {
				t.handlePodsFromDeploymentStatus(&status, ts)
				t.handleDeploymentStatus(&status, ts)
				abort, abortErr = t.handleTaskStateStatus(ts)
			})

			if abort {
				return abortErr
			}
		case logChunk := <-tracker.PodLogChunk:
			t.taskState.RTransaction(func(ts *statestore.ReadinessTaskState) {
				t.logStore.RWTransaction(func(ls *logstore.LogStore) {
					t.handleReplicaSetPodLogChunk(logChunk, ls, ts)
				})
			})
		case msg := <-tracker.EventMsg:
			t.taskState.RTransaction(func(ts *statestore.ReadinessTaskState) {
				t.handleEventMessage(msg, ts, time.Now())
			})
		case report := <-tracker.PodError:
			var (
				abort    bool
				abortErr error
			)
			t.taskState.RWTransaction(func(ts *statestore.ReadinessTaskState) {
				t.handlePodsFromDeploymentStatus(&report.DeploymentStatus, ts)
				t.handleDeploymentStatus(&report.DeploymentStatus, ts)
				t.handleReplicaSetPodError(&report.ReplicaSetPodError, ts)
				abort, abortErr = t.handleTaskStateStatus(ts)
			})

			if abort {
				return abortErr
			}
		}
	}
}

func (t *DynamicReadinessTracker) trackStatefulSet(ctx context.Context, tracker *statefulset.Tracker) error {
	trackCtx, trackCtxCancelFn := watchtools.ContextWithOptionalTimeout(ctx, t.timeout)
	defer trackCtxCancelFn()

	trackErrCh := make(chan error, 1)
	go func() {
		trackErrCh <- tracker.Track(trackCtx)
	}()

	for {
		select {
		case err := <-trackErrCh:
			if err != nil && !errors.Is(err, commontracker.ErrStopTrack) {
				return fmt.Errorf("track resource %q: %w", t.resourceHumanID, err)
			}

			return nil
		case status := <-tracker.Added:
			var (
				abort    bool
				abortErr error
			)
			t.taskState.RWTransaction(func(ts *statestore.ReadinessTaskState) {
				t.handlePodsFromStatefulSetStatus(&status, ts)
				t.handleStatefulSetStatus(&status, ts)
				t.setRootResourceCreated(ts)
				abort, abortErr = t.handleTaskStateStatus(ts)
			})

			if abort {
				return abortErr
			}
		case status := <-tracker.Ready:
			var (
				abort    bool
				abortErr error
			)
			status.IsReady = true

			t.taskState.RWTransaction(func(ts *statestore.ReadinessTaskState) {
				t.handlePodsFromStatefulSetStatus(&status, ts)
				t.handleStatefulSetStatus(&status, ts)
				abort, abortErr = t.handleTaskStateStatus(ts)
			})

			if abort {
				return abortErr
			}
		case report := <-tracker.AddedPod:
			var (
				abort    bool
				abortErr error
			)
			t.taskState.RWTransaction(func(ts *statestore.ReadinessTaskState) {
				t.handlePodsFromStatefulSetStatus(&report.StatefulSetStatus, ts)
				t.handlePodsFromStatefulSetPodAddedReport(&report, ts)
				t.handleStatefulSetStatus(&report.StatefulSetStatus, ts)
				abort, abortErr = t.handleTaskStateStatus(ts)
			})

			if abort {
				return abortErr
			}
		case status := <-tracker.Failed:
			var (
				abort    bool
				abortErr error
			)
			t.taskState.RWTransaction(func(ts *statestore.ReadinessTaskState) {
				t.handlePodsFromStatefulSetStatus(&status, ts)
				t.handleStatefulSetStatus(&status, ts)
				abort, abortErr = t.handleTaskStateStatus(ts)
			})

			if abort {
				return abortErr
			}
		case status := <-tracker.Status:
			var (
				abort    bool
				abortErr error
			)
			t.taskState.RWTransaction(func(ts *statestore.ReadinessTaskState) {
				t.handlePodsFromStatefulSetStatus(&status, ts)
				t.handleStatefulSetStatus(&status, ts)
				abort, abortErr = t.handleTaskStateStatus(ts)
			})

			if abort {
				return abortErr
			}
		case logChunk := <-tracker.PodLogChunk:
			t.taskState.RTransaction(func(ts *statestore.ReadinessTaskState) {
				t.logStore.RWTransaction(func(ls *logstore.LogStore) {
					t.handlePodLogChunk(logChunk.PodLogChunk, ls, ts)
				})
			})
		case msg := <-tracker.EventMsg:
			t.taskState.RTransaction(func(ts *statestore.ReadinessTaskState) {
				t.handleEventMessage(msg, ts, time.Now())
			})
		case report := <-tracker.PodError:
			var (
				abort    bool
				abortErr error
			)
			t.taskState.RWTransaction(func(ts *statestore.ReadinessTaskState) {
				t.handlePodsFromStatefulSetStatus(&report.StatefulSetStatus, ts)
				t.handleStatefulSetStatus(&report.StatefulSetStatus, ts)
				t.handlePodError(&report.ReplicaSetPodError.PodError, ts)
				abort, abortErr = t.handleTaskStateStatus(ts)
			})

			if abort {
				return abortErr
			}
		}
	}
}

func (t *DynamicReadinessTracker) trackDaemonSet(ctx context.Context, tracker *daemonset.Tracker) error {
	trackCtx, trackCtxCancelFn := watchtools.ContextWithOptionalTimeout(ctx, t.timeout)
	defer trackCtxCancelFn()

	trackErrCh := make(chan error, 1)
	go func() {
		trackErrCh <- tracker.Track(trackCtx)
	}()

	for {
		select {
		case err := <-trackErrCh:
			if err != nil && !errors.Is(err, commontracker.ErrStopTrack) {
				return fmt.Errorf("track resource %q: %w", t.resourceHumanID, err)
			}

			return nil
		case status := <-tracker.Added:
			var (
				abort    bool
				abortErr error
			)
			t.taskState.RWTransaction(func(ts *statestore.ReadinessTaskState) {
				t.handlePodsFromDaemonSetStatus(&status, ts)
				t.handleDaemonSetStatus(&status, ts)
				t.setRootResourceCreated(ts)
				abort, abortErr = t.handleTaskStateStatus(ts)
			})

			if abort {
				return abortErr
			}
		case status := <-tracker.Ready:
			var (
				abort    bool
				abortErr error
			)
			status.IsReady = true

			t.taskState.RWTransaction(func(ts *statestore.ReadinessTaskState) {
				t.handlePodsFromDaemonSetStatus(&status, ts)
				t.handleDaemonSetStatus(&status, ts)
				abort, abortErr = t.handleTaskStateStatus(ts)
			})

			if abort {
				return abortErr
			}
		case report := <-tracker.AddedPod:
			var (
				abort    bool
				abortErr error
			)
			t.taskState.RWTransaction(func(ts *statestore.ReadinessTaskState) {
				t.handlePodsFromDaemonSetStatus(&report.DaemonSetStatus, ts)
				t.handlePodsFromDaemonSetPodAddedReport(&report, ts)
				t.handleDaemonSetStatus(&report.DaemonSetStatus, ts)
				abort, abortErr = t.handleTaskStateStatus(ts)
			})

			if abort {
				return abortErr
			}
		case status := <-tracker.Failed:
			var (
				abort    bool
				abortErr error
			)
			t.taskState.RWTransaction(func(ts *statestore.ReadinessTaskState) {
				t.handlePodsFromDaemonSetStatus(&status, ts)
				t.handleDaemonSetStatus(&status, ts)
				abort, abortErr = t.handleTaskStateStatus(ts)
			})

			if abort {
				return abortErr
			}
		case status := <-tracker.Status:
			var (
				abort    bool
				abortErr error
			)
			t.taskState.RWTransaction(func(ts *statestore.ReadinessTaskState) {
				t.handlePodsFromDaemonSetStatus(&status, ts)
				t.handleDaemonSetStatus(&status, ts)
				abort, abortErr = t.handleTaskStateStatus(ts)
			})

			if abort {
				return abortErr
			}
		case logChunk := <-tracker.PodLogChunk:
			t.taskState.RTransaction(func(ts *statestore.ReadinessTaskState) {
				t.logStore.RWTransaction(func(ls *logstore.LogStore) {
					t.handlePodLogChunk(logChunk.PodLogChunk, ls, ts)
				})
			})
		case msg := <-tracker.EventMsg:
			t.taskState.RTransaction(func(ts *statestore.ReadinessTaskState) {
				t.handleEventMessage(msg, ts, time.Now())
			})
		case report := <-tracker.PodError:
			var (
				abort    bool
				abortErr error
			)
			t.taskState.RWTransaction(func(ts *statestore.ReadinessTaskState) {
				t.handlePodsFromDaemonSetStatus(&report.DaemonSetStatus, ts)
				t.handleDaemonSetStatus(&report.DaemonSetStatus, ts)
				t.handlePodError(&report.PodError.PodError, ts)
				abort, abortErr = t.handleTaskStateStatus(ts)
			})

			if abort {
				return abortErr
			}
		}
	}
}

func (t *DynamicReadinessTracker) trackJob(ctx context.Context, tracker *job.Tracker) error {
	trackCtx, trackCtxCancelFn := watchtools.ContextWithOptionalTimeout(ctx, t.timeout)
	defer trackCtxCancelFn()

	trackErrCh := make(chan error, 1)
	go func() {
		trackErrCh <- tracker.Track(trackCtx)
	}()

	for {
		select {
		case err := <-trackErrCh:
			if err != nil && !errors.Is(err, commontracker.ErrStopTrack) {
				return fmt.Errorf("track resource %q: %w", t.resourceHumanID, err)
			}

			return nil
		case status := <-tracker.Added:
			var (
				abort    bool
				abortErr error
			)
			t.taskState.RWTransaction(func(ts *statestore.ReadinessTaskState) {
				t.handlePodsFromJobStatus(&status, ts)
				t.handleJobStatus(&status, ts)
				t.setRootResourceCreated(ts)
				abort, abortErr = t.handleTaskStateStatus(ts)
			})

			if abort {
				return abortErr
			}
		case status := <-tracker.Succeeded:
			var (
				abort    bool
				abortErr error
			)
			status.IsSucceeded = true

			t.taskState.RWTransaction(func(ts *statestore.ReadinessTaskState) {
				t.handlePodsFromJobStatus(&status, ts)
				t.handleJobStatus(&status, ts)
				abort, abortErr = t.handleTaskStateStatus(ts)
			})

			if abort {
				return abortErr
			}
		case report := <-tracker.AddedPod:
			var (
				abort    bool
				abortErr error
			)
			t.taskState.RWTransaction(func(ts *statestore.ReadinessTaskState) {
				t.handlePodsFromJobStatus(&report.JobStatus, ts)
				t.handlePodsFromJobPodAddedReport(&report, ts)
				t.handleJobStatus(&report.JobStatus, ts)
				abort, abortErr = t.handleTaskStateStatus(ts)
			})

			if abort {
				return abortErr
			}
		case status := <-tracker.Failed:
			var (
				abort    bool
				abortErr error
			)
			t.taskState.RWTransaction(func(ts *statestore.ReadinessTaskState) {
				t.handlePodsFromJobStatus(&status, ts)
				t.handleJobStatus(&status, ts)
				abort, abortErr = t.handleTaskStateStatus(ts)
			})

			if abort {
				return abortErr
			}
		case status := <-tracker.Status:
			var (
				abort    bool
				abortErr error
			)
			t.taskState.RWTransaction(func(ts *statestore.ReadinessTaskState) {
				t.handlePodsFromJobStatus(&status, ts)
				t.handleJobStatus(&status, ts)
				abort, abortErr = t.handleTaskStateStatus(ts)
			})

			if abort {
				return abortErr
			}
		case logChunk := <-tracker.PodLogChunk:
			t.taskState.RTransaction(func(ts *statestore.ReadinessTaskState) {
				t.logStore.RWTransaction(func(ls *logstore.LogStore) {
					t.handlePodLogChunk(logChunk, ls, ts)
				})
			})
		case msg := <-tracker.EventMsg:
			t.taskState.RTransaction(func(ts *statestore.ReadinessTaskState) {
				t.handleEventMessage(msg, ts, time.Now())
			})
		case report := <-tracker.PodError:
			var (
				abort    bool
				abortErr error
			)
			t.taskState.RWTransaction(func(ts *statestore.ReadinessTaskState) {
				t.handlePodsFromJobStatus(&report.JobStatus, ts)
				t.handleJobStatus(&report.JobStatus, ts)
				t.handlePodError(&report.PodError, ts)
				abort, abortErr = t.handleTaskStateStatus(ts)
			})

			if abort {
				return abortErr
			}
		}
	}
}

func (t *DynamicReadinessTracker) trackPod(ctx context.Context, tracker *pod.Tracker) error {
	trackCtx, trackCtxCancelFn := watchtools.ContextWithOptionalTimeout(ctx, t.timeout)
	defer trackCtxCancelFn()

	doneChan := make(chan struct{})
	trackErrCh := make(chan error, 1)

	go func() {
		if err := tracker.Start(trackCtx); err != nil {
			trackErrCh <- err
		} else {
			doneChan <- struct{}{}
		}
	}()

	for {
		select {
		case err := <-trackErrCh:
			if err != nil && !errors.Is(err, commontracker.ErrStopTrack) {
				return fmt.Errorf("track resource %q: %w", t.resourceHumanID, err)
			}

			return nil
		case status := <-tracker.Added:
			var (
				abort    bool
				abortErr error
			)
			t.taskState.RWTransaction(func(ts *statestore.ReadinessTaskState) {
				t.handlePodStatus(&status, ts)
				t.setRootResourceCreated(ts)
				abort, abortErr = t.handleTaskStateStatus(ts)
			})

			if abort {
				return abortErr
			}
		case status := <-tracker.Succeeded:
			var (
				abort    bool
				abortErr error
			)
			status.IsReady = true

			t.taskState.RWTransaction(func(ts *statestore.ReadinessTaskState) {
				t.handlePodStatus(&status, ts)
				abort, abortErr = t.handleTaskStateStatus(ts)
			})

			if abort {
				return abortErr
			}
		case status := <-tracker.Ready:
			var (
				abort    bool
				abortErr error
			)
			status.IsReady = true

			t.taskState.RWTransaction(func(ts *statestore.ReadinessTaskState) {
				t.handlePodStatus(&status, ts)
				abort, abortErr = t.handleTaskStateStatus(ts)
			})

			if abort {
				return abortErr
			}
		case report := <-tracker.Failed:
			var (
				abort    bool
				abortErr error
			)
			report.PodStatus.IsFailed = true

			t.taskState.RWTransaction(func(ts *statestore.ReadinessTaskState) {
				t.handlePodStatus(&report.PodStatus, ts)
				abort, abortErr = t.handleTaskStateStatus(ts)
			})

			if abort {
				return abortErr
			}
		case status := <-tracker.Status:
			var (
				abort    bool
				abortErr error
			)
			t.taskState.RWTransaction(func(ts *statestore.ReadinessTaskState) {
				t.handlePodStatus(&status, ts)
				abort, abortErr = t.handleTaskStateStatus(ts)
			})

			if abort {
				return abortErr
			}
		case msg := <-tracker.EventMsg:
			t.taskState.RTransaction(func(ts *statestore.ReadinessTaskState) {
				t.handleEventMessage(msg, ts, time.Now())
			})
		case chunk := <-tracker.ContainerLogChunk:
			t.taskState.RTransaction(func(ts *statestore.ReadinessTaskState) {
				t.logStore.RWTransaction(func(ls *logstore.LogStore) {
					t.handlePodLogChunk(&pod.PodLogChunk{ContainerLogChunk: chunk, PodName: tracker.ResourceName}, ls, ts)
				})
			})
		case <-doneChan:
			return nil
		}
	}
}

func (t *DynamicReadinessTracker) trackCanary(ctx context.Context, tracker *canary.Tracker) error {
	trackCtx, trackCtxCancelFn := watchtools.ContextWithOptionalTimeout(ctx, t.timeout)
	defer trackCtxCancelFn()

	trackErrCh := make(chan error, 1)
	go func() {
		trackErrCh <- tracker.Track(trackCtx)
	}()

	for {
		select {
		case err := <-trackErrCh:
			if err != nil && !errors.Is(err, commontracker.ErrStopTrack) {
				return fmt.Errorf("track resource %q: %w", t.resourceHumanID, err)
			}

			return nil
		case status := <-tracker.Added:
			var (
				abort    bool
				abortErr error
			)
			t.taskState.RWTransaction(func(ts *statestore.ReadinessTaskState) {
				t.handleCanaryStatus(&status, ts)
				t.setRootResourceCreated(ts)
				abort, abortErr = t.handleTaskStateStatus(ts)
			})

			if abort {
				return abortErr
			}
		case status := <-tracker.Succeeded:
			var (
				abort    bool
				abortErr error
			)
			status.IsSucceeded = true

			t.taskState.RWTransaction(func(ts *statestore.ReadinessTaskState) {
				t.handleCanaryStatus(&status, ts)
				abort, abortErr = t.handleTaskStateStatus(ts)
			})

			if abort {
				return abortErr
			}
		case status := <-tracker.Failed:
			var (
				abort    bool
				abortErr error
			)
			t.taskState.RWTransaction(func(ts *statestore.ReadinessTaskState) {
				t.handleCanaryStatus(&status, ts)
				abort, abortErr = t.handleTaskStateStatus(ts)
			})

			if abort {
				return abortErr
			}
		case status := <-tracker.Status:
			var (
				abort    bool
				abortErr error
			)
			t.taskState.RWTransaction(func(ts *statestore.ReadinessTaskState) {
				t.handleCanaryStatus(&status, ts)
				abort, abortErr = t.handleTaskStateStatus(ts)
			})

			if abort {
				return abortErr
			}
		case msg := <-tracker.EventMsg:
			t.taskState.RTransaction(func(ts *statestore.ReadinessTaskState) {
				t.handleEventMessage(msg, ts, time.Now())
			})
		}
	}
}

func (t *DynamicReadinessTracker) trackGeneric(ctx context.Context, tracker *generic.Tracker) error {
	trackCtx, trackCtxCancelFn := watchtools.ContextWithOptionalTimeout(ctx, t.timeout)
	defer trackCtxCancelFn()

	addedCh := make(chan *generic.ResourceStatus)
	succeededCh := make(chan *generic.ResourceStatus)
	failedCh := make(chan *generic.ResourceStatus)
	regularCh := make(chan *generic.ResourceStatus, 100)
	eventCh := make(chan *corev1.Event)

	trackErrCh := make(chan error, 1)
	go func() {
		trackErrCh <- tracker.Track(trackCtx, t.noActivityTimeout, addedCh, succeededCh, failedCh, regularCh, eventCh)
	}()

	for {
		select {
		case err := <-trackErrCh:
			if err != nil && !errors.Is(err, commontracker.ErrStopTrack) {
				return fmt.Errorf("track resource %q: %w", t.resourceHumanID, err)
			}

			return nil
		case status := <-addedCh:
			var (
				abort    bool
				abortErr error
			)
			t.taskState.RWTransaction(func(ts *statestore.ReadinessTaskState) {
				t.handleGenericResourceStatus(status, ts)
				t.setRootResourceCreated(ts)
				abort, abortErr = t.handleTaskStateStatus(ts)
			})

			if abort {
				return abortErr
			}
		case status := <-succeededCh:
			var (
				abort    bool
				abortErr error
			)
			t.taskState.RWTransaction(func(ts *statestore.ReadinessTaskState) {
				t.handleGenericResourceStatus(status, ts)
				abort, abortErr = t.handleTaskStateStatus(ts)
			})

			if abort {
				return abortErr
			}
		case status := <-failedCh:
			var (
				abort    bool
				abortErr error
			)
			t.taskState.RWTransaction(func(ts *statestore.ReadinessTaskState) {
				t.handleGenericResourceStatus(status, ts)
				abort, abortErr = t.handleTaskStateStatus(ts)
			})

			if abort {
				return abortErr
			}
		case status := <-regularCh:
			var (
				abort    bool
				abortErr error
			)
			t.taskState.RWTransaction(func(ts *statestore.ReadinessTaskState) {
				t.handleGenericResourceStatus(status, ts)
				abort, abortErr = t.handleTaskStateStatus(ts)
			})

			if abort {
				return abortErr
			}
		case event := <-eventCh:
			t.taskState.RTransaction(func(ts *statestore.ReadinessTaskState) {
				t.handleEventMessage(event.Message, ts, event.EventTime.Time)
			})
		}
	}
}

func (t *DynamicReadinessTracker) handlePodsFromDeploymentStatus(status *deployment.DeploymentStatus, taskState *statestore.ReadinessTaskState) {
	pods := lo.PickBy(status.Pods, func(_ string, podStatus pod.PodStatus) bool {
		return lo.Contains(status.NewPodsNames, podStatus.Name)
	})

	for _, pod := range pods {
		taskState.AddResourceState(pod.Name, taskState.Namespace(), podGvk)
		taskState.AddDependency(taskState.Name(), taskState.Namespace(), taskState.GroupVersionKind(), pod.Name, taskState.Namespace(), podGvk)

		if pod.StatusIndicator != nil {
			taskState.ResourceState(pod.Name, taskState.Namespace(), podGvk).RWTransaction(func(rs *statestore.ResourceState) {
				setPodStatusAttribute(rs, pod.StatusIndicator.Value)
			})
		}
	}
}

func (t *DynamicReadinessTracker) handlePodsFromStatefulSetStatus(status *statefulset.StatefulSetStatus, taskState *statestore.ReadinessTaskState) {
	pods := lo.PickBy(status.Pods, func(_ string, podStatus pod.PodStatus) bool {
		return lo.Contains(status.NewPodsNames, podStatus.Name)
	})

	for _, pod := range pods {
		taskState.AddResourceState(pod.Name, taskState.Namespace(), podGvk)
		taskState.AddDependency(taskState.Name(), taskState.Namespace(), taskState.GroupVersionKind(), pod.Name, taskState.Namespace(), podGvk)

		if pod.StatusIndicator != nil {
			taskState.ResourceState(pod.Name, taskState.Namespace(), podGvk).RWTransaction(func(rs *statestore.ResourceState) {
				setPodStatusAttribute(rs, pod.StatusIndicator.Value)
			})
		}
	}
}

func (t *DynamicReadinessTracker) handlePodsFromDaemonSetStatus(status *daemonset.DaemonSetStatus, taskState *statestore.ReadinessTaskState) {
	pods := lo.PickBy(status.Pods, func(_ string, podStatus pod.PodStatus) bool {
		return lo.Contains(status.NewPodsNames, podStatus.Name)
	})

	for _, pod := range pods {
		taskState.AddResourceState(pod.Name, taskState.Namespace(), podGvk)
		taskState.AddDependency(taskState.Name(), taskState.Namespace(), taskState.GroupVersionKind(), pod.Name, taskState.Namespace(), podGvk)

		if pod.StatusIndicator != nil {
			taskState.ResourceState(pod.Name, taskState.Namespace(), podGvk).RWTransaction(func(rs *statestore.ResourceState) {
				setPodStatusAttribute(rs, pod.StatusIndicator.Value)
			})
		}
	}
}

func (t *DynamicReadinessTracker) handlePodsFromJobStatus(status *job.JobStatus, taskState *statestore.ReadinessTaskState) {
	for _, pod := range status.Pods {
		taskState.AddResourceState(pod.Name, taskState.Namespace(), podGvk)
		taskState.AddDependency(taskState.Name(), taskState.Namespace(), taskState.GroupVersionKind(), pod.Name, taskState.Namespace(), podGvk)

		if pod.StatusIndicator != nil {
			taskState.ResourceState(pod.Name, taskState.Namespace(), podGvk).RWTransaction(func(rs *statestore.ResourceState) {
				setPodStatusAttribute(rs, pod.StatusIndicator.Value)
			})
		}
	}
}

func (t *DynamicReadinessTracker) handlePodStatus(status *pod.PodStatus, taskState *statestore.ReadinessTaskState) {
	taskState.AddResourceState(status.Name, taskState.Namespace(), podGvk)

	if status.StatusIndicator != nil {
		taskState.ResourceState(status.Name, taskState.Namespace(), podGvk).RWTransaction(func(rs *statestore.ResourceState) {
			setPodStatusAttribute(rs, status.StatusIndicator.Value)
		})
	}

	if status.IsReady {
		taskState.SetStatus(statestore.ReadinessTaskStatusReady)

		for _, state := range taskState.ResourceStates() {
			state.RWTransaction(func(rs *statestore.ResourceState) {
				rs.SetStatus(statestore.ResourceStatusReady)
			})
		}

		return
	}

	if status.IsFailed {
		taskState.ResourceState(taskState.Name(), taskState.Namespace(), taskState.GroupVersionKind()).RWTransaction(func(rs *statestore.ResourceState) {
			rs.AddError(errors.New(status.FailedReason), "", time.Now())
		})

		return
	}
}

func (t *DynamicReadinessTracker) handlePodsFromDeploymentPodAddedReport(report *deployment.PodAddedReport, taskState *statestore.ReadinessTaskState) {
	if !report.ReplicaSetPod.ReplicaSet.IsNew {
		return
	}

	taskState.AddResourceState(report.ReplicaSetPod.Name, taskState.Namespace(), podGvk)
	taskState.AddDependency(taskState.Name(), taskState.Namespace(), taskState.GroupVersionKind(), report.ReplicaSetPod.Name, taskState.Namespace(), podGvk)

	for _, pod := range report.DeploymentStatus.Pods {
		if pod.StatusIndicator != nil {
			taskState.ResourceState(report.ReplicaSetPod.Name, taskState.Namespace(), podGvk).RWTransaction(func(rs *statestore.ResourceState) {
				setPodStatusAttribute(rs, pod.StatusIndicator.Value)
			})
		}
	}
}

func (t *DynamicReadinessTracker) handlePodsFromStatefulSetPodAddedReport(report *statefulset.PodAddedReport, taskState *statestore.ReadinessTaskState) {
	taskState.AddResourceState(report.ReplicaSetPod.Name, taskState.Namespace(), podGvk)
	taskState.AddDependency(taskState.Name(), taskState.Namespace(), taskState.GroupVersionKind(), report.ReplicaSetPod.Name, taskState.Namespace(), podGvk)

	for _, pod := range report.StatefulSetStatus.Pods {
		if pod.StatusIndicator != nil {
			taskState.ResourceState(report.ReplicaSetPod.Name, taskState.Namespace(), podGvk).RWTransaction(func(rs *statestore.ResourceState) {
				setPodStatusAttribute(rs, pod.StatusIndicator.Value)
			})
		}
	}
}

func (t *DynamicReadinessTracker) handlePodsFromDaemonSetPodAddedReport(report *daemonset.PodAddedReport, taskState *statestore.ReadinessTaskState) {
	taskState.AddResourceState(report.Pod.Name, taskState.Namespace(), podGvk)
	taskState.AddDependency(taskState.Name(), taskState.Namespace(), taskState.GroupVersionKind(), report.Pod.Name, taskState.Namespace(), podGvk)

	for _, pod := range report.DaemonSetStatus.Pods {
		if pod.StatusIndicator != nil {
			taskState.ResourceState(report.Pod.Name, taskState.Namespace(), podGvk).RWTransaction(func(rs *statestore.ResourceState) {
				setPodStatusAttribute(rs, pod.StatusIndicator.Value)
			})
		}
	}
}

func (t *DynamicReadinessTracker) handlePodsFromJobPodAddedReport(report *job.PodAddedReport, taskState *statestore.ReadinessTaskState) {
	taskState.AddResourceState(report.PodName, taskState.Namespace(), podGvk)
	taskState.AddDependency(taskState.Name(), taskState.Namespace(), taskState.GroupVersionKind(), report.PodName, taskState.Namespace(), podGvk)

	for _, pod := range report.JobStatus.Pods {
		if pod.StatusIndicator != nil {
			taskState.ResourceState(report.PodName, taskState.Namespace(), podGvk).RWTransaction(func(rs *statestore.ResourceState) {
				setPodStatusAttribute(rs, pod.StatusIndicator.Value)
			})
		}
	}
}

func (t *DynamicReadinessTracker) handleDeploymentStatus(status *deployment.DeploymentStatus, taskState *statestore.ReadinessTaskState) {
	if status.ReplicasIndicator != nil {
		taskState.ResourceState(taskState.Name(), taskState.Namespace(), taskState.GroupVersionKind()).RWTransaction(func(rs *statestore.ResourceState) {
			setReplicasAttribute(rs, int(status.ReplicasIndicator.TargetValue))
		})
	}

	if status.IsReady {
		taskState.SetStatus(statestore.ReadinessTaskStatusReady)

		for _, state := range taskState.ResourceStates() {
			state.RWTransaction(func(rs *statestore.ResourceState) {
				rs.SetStatus(statestore.ResourceStatusReady)
			})
		}

		return
	}

	if status.IsFailed {
		taskState.ResourceState(taskState.Name(), taskState.Namespace(), taskState.GroupVersionKind()).RWTransaction(func(rs *statestore.ResourceState) {
			rs.AddError(errors.New(status.FailedReason), "", time.Now())
			if status.FailureMode == deployment.FailureModeFatal {
				rs.SetStatus(statestore.ResourceStatusFailed)
			}
		})
	}
}

func (t *DynamicReadinessTracker) handleStatefulSetStatus(status *statefulset.StatefulSetStatus, taskState *statestore.ReadinessTaskState) {
	if status.ReplicasIndicator != nil {
		taskState.ResourceState(taskState.Name(), taskState.Namespace(), taskState.GroupVersionKind()).RWTransaction(func(rs *statestore.ResourceState) {
			setReplicasAttribute(rs, int(status.ReplicasIndicator.TargetValue))
		})
	}

	if status.IsReady {
		taskState.SetStatus(statestore.ReadinessTaskStatusReady)

		for _, state := range taskState.ResourceStates() {
			state.RWTransaction(func(rs *statestore.ResourceState) {
				rs.SetStatus(statestore.ResourceStatusReady)
			})
		}

		return
	}

	if status.IsFailed {
		taskState.ResourceState(taskState.Name(), taskState.Namespace(), taskState.GroupVersionKind()).RWTransaction(func(rs *statestore.ResourceState) {
			rs.AddError(errors.New(status.FailedReason), "", time.Now())
		})
	}
}

func (t *DynamicReadinessTracker) handleDaemonSetStatus(status *daemonset.DaemonSetStatus, taskState *statestore.ReadinessTaskState) {
	if status.ReplicasIndicator != nil {
		taskState.ResourceState(taskState.Name(), taskState.Namespace(), taskState.GroupVersionKind()).RWTransaction(func(rs *statestore.ResourceState) {
			setReplicasAttribute(rs, int(status.ReplicasIndicator.TargetValue))
		})
	}

	if status.IsReady {
		taskState.SetStatus(statestore.ReadinessTaskStatusReady)

		for _, state := range taskState.ResourceStates() {
			state.RWTransaction(func(rs *statestore.ResourceState) {
				rs.SetStatus(statestore.ResourceStatusReady)
			})
		}

		return
	}

	if status.IsFailed {
		taskState.ResourceState(taskState.Name(), taskState.Namespace(), taskState.GroupVersionKind()).RWTransaction(func(rs *statestore.ResourceState) {
			rs.AddError(errors.New(status.FailedReason), "", time.Now())
		})
	}
}

func (t *DynamicReadinessTracker) handleJobStatus(status *job.JobStatus, taskState *statestore.ReadinessTaskState) {
	taskState.ResourceState(taskState.Name(), taskState.Namespace(), taskState.GroupVersionKind()).RWTransaction(func(rs *statestore.ResourceState) {
		setReplicasAttribute(rs, 1)
	})

	if status.IsSucceeded {
		taskState.SetStatus(statestore.ReadinessTaskStatusReady)

		for _, state := range taskState.ResourceStates() {
			state.RWTransaction(func(rs *statestore.ResourceState) {
				rs.SetStatus(statestore.ResourceStatusReady)
			})
		}

		return
	}

	if status.IsFailed {
		taskState.ResourceState(taskState.Name(), taskState.Namespace(), taskState.GroupVersionKind()).RWTransaction(func(rs *statestore.ResourceState) {
			rs.AddError(errors.New(status.FailedReason), "", time.Now())
		})
	}
}

func (t *DynamicReadinessTracker) handleCanaryStatus(status *canary.CanaryStatus, taskState *statestore.ReadinessTaskState) {
	if status.IsSucceeded {
		taskState.SetStatus(statestore.ReadinessTaskStatusReady)

		for _, state := range taskState.ResourceStates() {
			state.RWTransaction(func(rs *statestore.ResourceState) {
				rs.SetStatus(statestore.ResourceStatusReady)
			})
		}

		return
	}

	if status.IsFailed {
		taskState.ResourceState(taskState.Name(), taskState.Namespace(), taskState.GroupVersionKind()).RWTransaction(func(rs *statestore.ResourceState) {
			rs.AddError(errors.New(status.FailedReason), "", time.Now())
		})
	}
}

func (t *DynamicReadinessTracker) handleGenericResourceStatus(status *generic.ResourceStatus, taskState *statestore.ReadinessTaskState) {
	if status.Indicator != nil {
		taskState.ResourceState(taskState.Name(), taskState.Namespace(), taskState.GroupVersionKind()).RWTransaction(func(rs *statestore.ResourceState) {
			setGenericConditionAttributes(rs, status)
		})
	}

	if status.IsReady() {
		taskState.SetStatus(statestore.ReadinessTaskStatusReady)

		for _, state := range taskState.ResourceStates() {
			state.RWTransaction(func(rs *statestore.ResourceState) {
				rs.SetStatus(statestore.ResourceStatusReady)
			})
		}

		return
	}

	if status.IsFailed() {
		taskState.ResourceState(taskState.Name(), taskState.Namespace(), taskState.GroupVersionKind()).RWTransaction(func(rs *statestore.ResourceState) {
			rs.AddError(errors.New(status.FailureReason()), "", time.Now())
		})

		return
	}

	if status.IsDeleted() {
		for _, state := range taskState.ResourceStates() {
			state.RWTransaction(func(rs *statestore.ResourceState) {
				rs.SetStatus(statestore.ResourceStatusDeleted)
			})
		}
	}
}

func (t *DynamicReadinessTracker) handleReplicaSetPodError(podError *replicaset.ReplicaSetPodError, taskState *statestore.ReadinessTaskState) {
	if !podError.ReplicaSet.IsNew {
		return
	}

	t.handlePodError(&podError.PodError, taskState)
}

func (t *DynamicReadinessTracker) handlePodError(podError *pod.PodError, taskState *statestore.ReadinessTaskState) {
	podState := taskState.ResourceState(podError.PodName, taskState.Namespace(), podGvk)

	podState.RWTransaction(func(rs *statestore.ResourceState) {
		rs.AddError(errors.New(podError.Message), podError.ContainerName, time.Now())
	})
}

func (t *DynamicReadinessTracker) handleReplicaSetPodLogChunk(logChunk *replicaset.ReplicaSetPodLogChunk, logStore *logstore.LogStore, taskState *statestore.ReadinessTaskState) {
	if !logChunk.ReplicaSet.IsNew {
		return
	}

	t.handlePodLogChunk(logChunk.PodLogChunk, logStore, taskState)
}

func (t *DynamicReadinessTracker) handlePodLogChunk(logChunk *pod.PodLogChunk, logStore *logstore.LogStore, taskState *statestore.ReadinessTaskState) {
	if t.ignoreLogs {
		return
	}

	for _, ignoreLogForContainer := range t.ignoreLogsForContainers {
		if ignoreLogForContainer == logChunk.ContainerName {
			return
		}
	}

	if len(t.saveLogsOnlyForContainers) > 0 {
		var save bool
		for _, saveLogsOnlyForContainer := range t.saveLogsOnlyForContainers {
			if saveLogsOnlyForContainer == logChunk.ContainerName {
				save = true
				break
			}
		}
		if !save {
			return
		}
	}

	logLines := logChunk.LogLines

	if t.ignoreLogsByRegex != nil {
		var filteredLogLines []log.LogLine
		for _, logLine := range logLines {
			if !t.ignoreLogsByRegex.MatchString(logLine.Message) {
				filteredLogLines = append(filteredLogLines, logLine)
			}
		}
		logLines = filteredLogLines
	}

	if len(t.ignoreLogsByRegexForContainers) > 0 {
		if regex, ok := t.ignoreLogsByRegexForContainers[logChunk.ContainerName]; ok {
			var filteredLogLines []log.LogLine
			for _, logLine := range logLines {
				if !regex.MatchString(logLine.Message) {
					filteredLogLines = append(filteredLogLines, logLine)
				}
			}
			logLines = filteredLogLines
		}
	}

	if t.saveLogsByRegex != nil {
		var filteredLogLines []log.LogLine
		for _, logLine := range logLines {
			if t.saveLogsByRegex.MatchString(logLine.Message) {
				filteredLogLines = append(filteredLogLines, logLine)
			}
		}
		logLines = filteredLogLines
	}

	if len(t.saveLogsByRegexForContainers) > 0 {
		if regex, ok := t.saveLogsByRegexForContainers[logChunk.ContainerName]; ok {
			var filteredLogLines []log.LogLine
			for _, logLine := range logLines {
				if regex.MatchString(logLine.Message) {
					filteredLogLines = append(filteredLogLines, logLine)
				}
			}
			logLines = filteredLogLines
		}
	}

	if len(logLines) == 0 {
		return
	}

	// Filtering ran on the original message bodies above, so save/ignore
	// selection keeps its historical semantics. Redaction happens only now,
	// after selection and before anything reaches the log store or a display
	// consumer: no unredacted value is ever persisted by this tracker.
	logLines = t.redactLogLines(logChunk.PodName, logChunk.ContainerName, logLines)
	if len(logLines) == 0 {
		return
	}

	namespace := taskState.Namespace()

	var resourceLogs *util.Concurrent[*logstore.ResourceLogs]
	if foundResourceLogs, found := lo.Find(logStore.ResourcesLogs(), func(crl *util.Concurrent[*logstore.ResourceLogs]) bool {
		var found bool
		crl.RTransaction(func(rl *logstore.ResourceLogs) {
			found = rl.Name() == logChunk.PodName && rl.Namespace() == namespace && rl.GroupVersionKind() == podGvk
		})

		return found
	}); found {
		resourceLogs = foundResourceLogs
	} else {
		resourceLogs = util.NewConcurrent(
			logstore.NewResourceLogs(logChunk.PodName, namespace, podGvk),
		)
		logStore.AddResourceLogs(resourceLogs)
	}

	for _, line := range logLines {
		resourceLogs.RWTransaction(func(rl *logstore.ResourceLogs) {
			rl.AddLogLine(line.Message, "container/"+logChunk.ContainerName, lo.Must(time.Parse(time.RFC3339, line.Timestamp)))
		})
	}
}

// redactLogLines applies the configured redaction rules to the message bodies
// of logLines, preserving order and leaving Timestamp untouched. With no
// configuration it returns the input unchanged (same slice, same strings), so
// the disabled feature is byte-identical to the previous behavior.
//
// Each (pod, container) source gets its own redactor: residual multiline
// window content of one source can never influence another source. The output
// contains at least as many lines as the input over the stream's lifetime
// (redaction replaces values, it never deletes a line); a single call may
// return additional lines when the bounded window releases previously held
// content together with the current lines.
func (t *DynamicReadinessTracker) redactLogLines(podName, containerName string, logLines []log.LogLine) []log.LogLine {
	if t.redactLogsConfig == nil || len(logLines) == 0 {
		return logLines
	}

	key := podName + "\x00" + containerName
	r, ok := t.redactLogsEngines[key]
	if !ok {
		r = &logRedactor{engine: redaction.NewEngine(t.redactLogsConfig)}
		t.redactLogsEngines[key] = r
	}
	if !r.engine.Enabled() {
		return logLines
	}

	out := make([]log.LogLine, 0, len(logLines))
	for _, line := range logLines {
		// Timestamps stay outside the redaction domain: rules only see the
		// message body.
		result := r.engine.ProcessLine(line.Message)
		emitted := result.Emitted
		evicted := result.Evicted

		// Eviction always pops the oldest head lines; save their original
		// timestamps first, then emit evicted lines before the current line
		// so stream order never changes.
		evictedTimestamps := make([]string, 0, evicted)
		for i := 0; i < evicted && len(r.timestamps) > 0; i++ {
			evictedTimestamps = append(evictedTimestamps, r.timestamps[0])
			r.timestamps = r.timestamps[1:]
		}

		for i := 0; i < evicted && i < len(emitted); i++ {
			ts := ""
			if i < len(evictedTimestamps) {
				ts = evictedTimestamps[i]
			}
			out = append(out, log.LogLine{Timestamp: ts, Message: emitted[i]})
		}

		// The fed line is itself the last emission when it was not buffered.
		if evicted < len(emitted) {
			out = append(out, log.LogLine{Timestamp: line.Timestamp, Message: emitted[len(emitted)-1]})
		}

		// Keep the timestamp queue 1:1 aligned with the engine window.
		heldAfter := r.engine.WindowSize()
		if evicted == len(emitted) {
			for len(r.timestamps) < heldAfter {
				r.timestamps = append(r.timestamps, line.Timestamp)
			}
		}
		for len(r.timestamps) > heldAfter {
			r.timestamps = r.timestamps[:len(r.timestamps)-1]
		}
	}

	return out
}

// flushRedaction releases every line still held in a source's bounded
// multiline window at stream end, each with its original timestamp. It never
// blocks waiting for a multiline end marker that may never arrive.
func (t *DynamicReadinessTracker) flushRedaction(podName, containerName string) []log.LogLine {
	if t.redactLogsConfig == nil {
		return nil
	}

	key := podName + "\x00" + containerName
	r, ok := t.redactLogsEngines[key]
	if !ok || !r.engine.Enabled() {
		return nil
	}

	messages := r.engine.Flush()
	if len(messages) == 0 {
		r.timestamps = r.timestamps[:0]
		return nil
	}

	lines := make([]log.LogLine, 0, len(messages))
	for i, message := range messages {
		ts := ""
		if i < len(r.timestamps) {
			ts = r.timestamps[i]
		}
		lines = append(lines, log.LogLine{Timestamp: ts, Message: message})
	}
	r.timestamps = r.timestamps[:0]

	return lines
}

// resetRedaction discards all redaction window state for a source. Use it on
// container switches / stream teardown so no residual bytes survive the
// source identity change.
func (t *DynamicReadinessTracker) resetRedaction(podName, containerName string) {
	if t.redactLogsConfig == nil {
		return
	}

	key := podName + "\x00" + containerName
	delete(t.redactLogsEngines, key)
}

// FlushLogRedaction releases every line still held in the bounded multiline
// window of one (pod, container) source and stores it through the regular log
// path, preserving order, source identifier and the original timestamps.
//
// It is meant to be called when the caller knows the container stream ended
// (for example after a log relay goroutine observed EOF). Calling it is never
// required for correctness of masking: the window bounds guarantee buffered
// content is released on its own, it only controls promptness at stream end.
// It is safe to call for unknown or unconfigured sources (returns without
// changes) and may be called repeatedly.
func (t *DynamicReadinessTracker) FlushLogRedaction(podName, containerName string) {
	if t.redactLogsConfig == nil {
		return
	}

	lines := t.flushRedaction(podName, containerName)
	if len(lines) == 0 {
		return
	}

	t.logStore.RWTransaction(func(ls *logstore.LogStore) {
		var resourceLogs *util.Concurrent[*logstore.ResourceLogs]
		namespace := t.taskStateObject().Namespace()

		if found, ok := lo.Find(ls.ResourcesLogs(), func(crl *util.Concurrent[*logstore.ResourceLogs]) bool {
			var found bool
			crl.RTransaction(func(rl *logstore.ResourceLogs) {
				found = rl.Name() == podName && rl.Namespace() == namespace && rl.GroupVersionKind() == podGvk
			})
			return found
		}); ok {
			resourceLogs = found
		} else {
			resourceLogs = util.NewConcurrent(logstore.NewResourceLogs(podName, namespace, podGvk))
			ls.AddResourceLogs(resourceLogs)
		}

		source := "container/" + containerName
		for _, line := range lines {
			// The timestamp queue is kept 1:1 with the engine window, so a
			// flushed line always carries its original RFC3339 timestamp. A
			// parse failure here would indicate an internal bookkeeping bug;
			// fall back to the current time rather than dropping the line or
			// inventing a malformed timestamp.
			ts, err := time.Parse(time.RFC3339, line.Timestamp)
			if err != nil {
				ts = time.Now()
			}
			resourceLogs.RWTransaction(func(rl *logstore.ResourceLogs) {
				rl.AddLogLine(line.Message, source, ts)
			})
		}
	})
}

// ResetLogRedaction drops all redaction state for one source. Call it when a
// container stream is torn down or its identity changes; afterwards a fresh
// stream of the same source starts with an empty window.
func (t *DynamicReadinessTracker) ResetLogRedaction(podName, containerName string) {
	t.resetRedaction(podName, containerName)
}

// taskStateObject safely reads the current task state for namespace lookups
// outside the main Track loop.
func (t *DynamicReadinessTracker) taskStateObject() *statestore.ReadinessTaskState {
	var ts *statestore.ReadinessTaskState
	t.taskState.RTransaction(func(state *statestore.ReadinessTaskState) {
		ts = state
	})
	return ts
}

func (t *DynamicReadinessTracker) handleEventMessage(msg string, taskState *statestore.ReadinessTaskState, timestamp time.Time) {
	if !t.saveEvents {
		return
	}

	resourceState := taskState.ResourceState(taskState.Name(), taskState.Namespace(), taskState.GroupVersionKind())

	resourceState.RWTransaction(func(rs *statestore.ResourceState) {
		rs.AddEvent(msg, timestamp)
	})
}

func (t *DynamicReadinessTracker) handleTaskStateStatus(taskState *statestore.ReadinessTaskState) (abort bool, abortErr error) {
	taskStateStatus := taskState.Status()
	switch taskStateStatus {
	case statestore.ReadinessTaskStatusProgressing:
	case statestore.ReadinessTaskStatusReady:
		abort = true
		return abort, abortErr
	case statestore.ReadinessTaskStatusFailed:
		abort = true
		abortErr = fmt.Errorf("waiting for resource %q readiness failed", t.resourceHumanID)
		return abort, abortErr
	default:
		panic("unexpected status")
	}

	return abort, abortErr
}

func (t *DynamicReadinessTracker) setRootResourceCreated(taskState *statestore.ReadinessTaskState) {
	rss := taskState.ResourceStates()

	if len(rss) == 0 {
		return
	}

	rss[0].RWTransaction(func(rs *statestore.ResourceState) {
		rs.SetStatus(statestore.ResourceStatusCreated)
	})
}

func setReplicasAttribute(resourceState *statestore.ResourceState, replicas int) {
	attributes := resourceState.Attributes()

	if replicasAttr, found := lo.Find(attributes, func(attr statestore.Attributer) bool {
		return attr.Name() == statestore.AttributeNameRequiredReplicas
	}); found {
		replicasAttr.(*statestore.Attribute[int]).Value = replicas
	} else {
		replicasAttr = statestore.NewAttribute(statestore.AttributeNameRequiredReplicas, replicas)
		resourceState.AddAttribute(replicasAttr)
	}
}

func setPodStatusAttribute(resourceState *statestore.ResourceState, status string) {
	attributes := resourceState.Attributes()

	if statusAttr, found := lo.Find(attributes, func(attr statestore.Attributer) bool {
		return attr.Name() == statestore.AttributeNameStatus
	}); found {
		statusAttr.(*statestore.Attribute[string]).Value = status
	} else {
		statusAttr = statestore.NewAttribute(statestore.AttributeNameStatus, status)
		resourceState.AddAttribute(statusAttr)
	}
}

func setGenericConditionAttributes(resourceState *statestore.ResourceState, resourceStatus *generic.ResourceStatus) {
	attributes := resourceState.Attributes()

	if conditionTargetAttr, found := lo.Find(attributes, func(attr statestore.Attributer) bool {
		return attr.Name() == statestore.AttributeNameConditionTarget
	}); found {
		conditionTargetAttr.(*statestore.Attribute[string]).Value = resourceStatus.HumanConditionPath()
	} else {
		conditionTargetAttr = statestore.NewAttribute(statestore.AttributeNameConditionTarget, resourceStatus.HumanConditionPath())
		resourceState.AddAttribute(conditionTargetAttr)
	}

	if resourceStatus.Indicator.Value != "" {
		if conditionCurrentValueAttr, found := lo.Find(attributes, func(attr statestore.Attributer) bool {
			return attr.Name() == statestore.AttributeNameConditionCurrentValue
		}); found {
			conditionCurrentValueAttr.(*statestore.Attribute[string]).Value = resourceStatus.Indicator.Value
		} else {
			conditionCurrentValueAttr = statestore.NewAttribute(statestore.AttributeNameConditionCurrentValue, resourceStatus.Indicator.Value)
			resourceState.AddAttribute(conditionCurrentValueAttr)
		}
	}
}

var podGvk = schema.GroupVersionKind{
	Group:   "",
	Version: "v1",
	Kind:    "Pod",
}
