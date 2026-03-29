package amz

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/skye-z/amz/internal/auth"
	amzconfig "github.com/skye-z/amz/internal/config"
	"github.com/skye-z/amz/internal/discovery"
	iruntime "github.com/skye-z/amz/internal/runtime"
	amzsession "github.com/skye-z/amz/internal/session"
	"github.com/skye-z/amz/internal/storage"
)

func init() {
	buildSDKRuntime = newManagedRuntime
}

type managedRuntime struct {
	mu         sync.Mutex
	opts       Options
	store      stateStore
	auth       authEnsurer
	runtime    sdkRuntime
	status     Status
	registered bool
	endpoint   string
	selectFn   func(context.Context, storage.State) (endpointSelection, []storage.Node, error)
	buildFn    func(string, storage.State) (sdkRuntime, error)
	selection  endpointSelection
	activeIdx  int
	lastState  storage.State
	switching  bool
}

type endpointSelection struct {
	Primary    discovery.Candidate
	Candidates []discovery.Candidate
}

type probeProfile struct {
	name                string
	perCandidateTimeout time.Duration
	batchTimeout        time.Duration
	concurrency         int
}

var defaultProbeProfile = probeProfile{
	name:                "default",
	perCandidateTimeout: time.Second,
	batchTimeout:        3 * time.Second,
	concurrency:         30,
}

var tunProbeProfile = probeProfile{
	name:                "tun",
	perCandidateTimeout: 7 * time.Second,
	batchTimeout:        10 * time.Second,
	concurrency:         4,
}

var validateTUNCandidateForSelection = func(ctx context.Context, opts Options, state storage.State, candidate discovery.Candidate) error {
	tunCfg := baseKernelConfigFromState(state, candidate.Address, strings.TrimSpace(opts.Transport.SNI), amzconfig.ModeTUN, "", withAction(opts.Logger, "SELECT"))
	connectionManager, err := amzsession.NewConnectionManager(tunCfg)
	if err != nil {
		return err
	}
	defer connectionManager.Close()
	if err := connectionManager.Connect(ctx); err != nil {
		return err
	}

	connectIPManager, err := amzsession.NewConnectIPSessionManager(tunCfg)
	if err != nil {
		return err
	}
	defer connectIPManager.Close()
	connectIPManager.UpdateSessionInfo(sessionInfoFromState(state))
	connectIPManager.BindHTTP3Conn(connectionManager.HTTP3Conn())
	if err := connectIPManager.Open(ctx); err != nil {
		return err
	}
	return nil
}

func newManagedRuntime(opts Options) (sdkRuntime, error) {
	path := strings.TrimSpace(opts.Storage.Path)
	if path == "" {
		defaultPath, err := storage.DefaultPath()
		if err != nil {
			return nil, err
		}
		path = defaultPath
		opts.Storage.Path = path
	}

	service, err := newDefaultAuthService(path)
	if err != nil {
		logEvent(opts.Logger, "managed_runtime", "new.failed",
			field("storage_path", path),
			field("error", err),
		)
		return nil, err
	}

	runtime := &managedRuntime{
		opts:  opts,
		store: storage.NewFileStore(path),
		auth:  service,
		status: Status{
			HTTPEnabled:   opts.HTTP.Enabled,
			SOCKS5Enabled: opts.SOCKS5.Enabled,
			TUNEnabled:    opts.TUN.Enabled,
		},
	}
	runtime.selectFn = runtime.selectEndpoint
	runtime.buildFn = runtime.buildRuntime
	logEvent(opts.Logger, "managed_runtime", "new.success",
		field("storage_path", path),
		field("http_enabled", opts.HTTP.Enabled),
		field("socks5_enabled", opts.SOCKS5.Enabled),
		field("tun_enabled", opts.TUN.Enabled),
		field("listen_address", opts.Listen.Address),
	)
	return runtime, nil
}

func (m *managedRuntime) Start(ctx context.Context) error {
	logger := m.opts.Logger
	started := time.Now()
	logEvent(logger, "managed_runtime", "start.begin",
		field("listen_address", m.opts.Listen.Address),
		field("http_enabled", m.opts.HTTP.Enabled),
		field("socks5_enabled", m.opts.SOCKS5.Enabled),
		field("tun_enabled", m.opts.TUN.Enabled),
	)

	m.mu.Lock()
	if m.runtime != nil {
		runtime := m.runtime
		m.mu.Unlock()
		logEvent(logger, "managed_runtime", "start.reuse_runtime")
		if err := runtime.Start(ctx); err != nil {
			logEvent(logger, "managed_runtime", "start.failed",
				field("error", err),
				durationField("duration", time.Since(started)),
			)
			return err
		}
		m.mu.Lock()
		m.refreshStatusLocked(runtime)
		status := m.status
		m.mu.Unlock()
		logEvent(logger, "managed_runtime", "start.success",
			field("endpoint", status.Endpoint),
			field("listen_address", status.ListenAddress),
			field("registered", status.Registered),
			field("running", status.Running),
			durationField("duration", time.Since(started)),
		)
		return nil
	}
	m.mu.Unlock()

	authStarted := time.Now()
	logEvent(logger, "managed_runtime", "auth.ensure.begin")
	authResult, err := m.auth.Ensure(ctx)
	if err != nil {
		logEvent(logger, "managed_runtime", "auth.ensure.failed",
			field("error", err),
			durationField("duration", time.Since(authStarted)),
		)
		logEvent(logger, "managed_runtime", "start.failed",
			field("error", err),
			durationField("duration", time.Since(started)),
		)
		return err
	}
	logEvent(logger, "managed_runtime", "auth.ensure.success",
		field("cache_nodes", len(authResult.State.NodeCache)),
		durationField("duration", time.Since(authStarted)),
	)

	state := authResult.State
	selectStarted := time.Now()
	logEvent(logger, "managed_runtime", "endpoint.select.begin",
		field("cache_nodes", len(state.NodeCache)),
		field("fixed_endpoint", strings.TrimSpace(m.opts.Transport.Endpoint)),
	)
	selection, cache, err := m.selectFn(ctx, state)
	if err != nil {
		logEvent(logger, "managed_runtime", "endpoint.select.failed",
			field("error", err),
			field("cache_nodes", len(state.NodeCache)),
			durationField("duration", time.Since(selectStarted)),
		)
		logEvent(logger, "managed_runtime", "start.failed",
			field("error", err),
			durationField("duration", time.Since(started)),
		)
		return err
	}
	if len(selection.Candidates) == 0 {
		err := fmt.Errorf("no available endpoint candidates")
		logEvent(logger, "managed_runtime", "endpoint.select.failed",
			field("error", err),
			field("cache_nodes", len(state.NodeCache)),
			durationField("duration", time.Since(selectStarted)),
		)
		logEvent(logger, "managed_runtime", "start.failed",
			field("error", err),
			durationField("duration", time.Since(started)),
		)
		return err
	}
	logEvent(logger, "managed_runtime", "endpoint.select.success",
		field("endpoint", selection.Primary.Address),
		field("source", selection.Primary.Source),
		field("candidate_count", len(selection.Candidates)),
		field("cache_nodes", len(cache)),
		durationField("duration", time.Since(selectStarted)),
	)
	var endpointErrors []error
	for idx, candidate := range selection.Candidates {
		if idx > 0 {
			logEvent(logger, "managed_runtime", "endpoint.failover",
				field("failed_endpoint", selection.Candidates[idx-1].Address),
				field("next_endpoint", candidate.Address),
				field("attempt", idx+1),
				field("total", len(selection.Candidates)),
			)
		}

		buildStarted := time.Now()
		logEvent(logger, "managed_runtime", "runtime.build.begin",
			field("endpoint", candidate.Address),
			field("http_enabled", m.opts.HTTP.Enabled),
			field("socks5_enabled", m.opts.SOCKS5.Enabled),
			field("tun_enabled", m.opts.TUN.Enabled),
		)
		runtime, buildErr := m.buildFn(candidate.Address, state)
		if buildErr != nil {
			logEvent(logger, "managed_runtime", "runtime.build.failed",
				field("endpoint", candidate.Address),
				field("error", buildErr),
				durationField("duration", time.Since(buildStarted)),
			)
			endpointErrors = append(endpointErrors, fmt.Errorf("%s build failed: %w", candidate.Address, buildErr))
			continue
		}
		logEvent(logger, "managed_runtime", "runtime.build.success",
			field("endpoint", candidate.Address),
			durationField("duration", time.Since(buildStarted)),
		)

		runtimeStartStarted := time.Now()
		logEvent(logger, "managed_runtime", "runtime.start.begin",
			field("endpoint", candidate.Address),
		)
		if startErr := runtime.Start(ctx); startErr != nil {
			logEvent(logger, "managed_runtime", "runtime.start.failed",
				field("endpoint", candidate.Address),
				field("error", startErr),
				durationField("duration", time.Since(runtimeStartStarted)),
			)
			endpointErrors = append(endpointErrors, fmt.Errorf("%s start failed: %w", candidate.Address, startErr))
			if closeErr := runtime.Close(); closeErr != nil {
				logEvent(logger, "managed_runtime", "runtime.close.failed",
					field("endpoint", candidate.Address),
					field("error", closeErr),
				)
			}
			continue
		}
		logEvent(logger, "managed_runtime", "runtime.start.success",
			field("endpoint", candidate.Address),
			durationField("duration", time.Since(runtimeStartStarted)),
		)
		if healthErr := m.runRuntimeHealthCheck(candidate.Address, runtime); healthErr != nil {
			logEvent(logger, "managed_runtime", "runtime.health.failed",
				field("endpoint", candidate.Address),
				field("error", healthErr),
			)
			endpointErrors = append(endpointErrors, fmt.Errorf("%s health check failed: %w", candidate.Address, healthErr))
			if closeErr := runtime.Close(); closeErr != nil {
				logEvent(logger, "managed_runtime", "runtime.close.failed",
					field("endpoint", candidate.Address),
					field("error", closeErr),
				)
			}
			continue
		}

		persistedState := state
		persistedState.SelectedNode = candidate.Address
		persistedState.NodeCache = cache
		saveStarted := time.Now()
		logEvent(logger, "managed_runtime", "state.save.begin",
			field("selected_node", persistedState.SelectedNode),
			field("cache_nodes", len(persistedState.NodeCache)),
		)
		if saveErr := m.store.Save(persistedState); saveErr != nil {
			logEvent(logger, "managed_runtime", "state.save.failed",
				field("selected_node", persistedState.SelectedNode),
				field("error", saveErr),
				durationField("duration", time.Since(saveStarted)),
			)
			_ = runtime.Close()
			logEvent(logger, "managed_runtime", "start.failed",
				field("error", saveErr),
				durationField("duration", time.Since(started)),
			)
			return saveErr
		}
		logEvent(logger, "managed_runtime", "state.save.success",
			field("selected_node", persistedState.SelectedNode),
			field("cache_nodes", len(persistedState.NodeCache)),
			durationField("duration", time.Since(saveStarted)),
		)

		m.mu.Lock()
		m.runtime = runtime
		m.registered = true
		m.endpoint = candidate.Address
		m.selection = selection
		m.activeIdx = idx
		m.lastState = persistedState
		m.switching = false
		m.refreshStatusLocked(runtime)
		status := m.status
		m.mu.Unlock()
		logEvent(logger, "managed_runtime", "start.success",
			field("endpoint", status.Endpoint),
			field("listen_address", status.ListenAddress),
			field("registered", status.Registered),
			field("running", status.Running),
			durationField("duration", time.Since(started)),
		)
		return nil
	}

	err = fmt.Errorf("all candidate endpoints failed: %w", errors.Join(endpointErrors...))
	logEvent(logger, "managed_runtime", "start.failed",
		field("error", err),
		durationField("duration", time.Since(started)),
	)
	return err
}

func (m *managedRuntime) Run() error {
	logger := m.opts.Logger
	started := time.Now()
	logEvent(logger, "managed_runtime", "run.begin")
	if err := m.Start(context.Background()); err != nil {
		logEvent(logger, "managed_runtime", "run.failed",
			field("error", err),
			durationField("duration", time.Since(started)),
		)
		return err
	}

	m.mu.Lock()
	runtime := m.runtime
	m.mu.Unlock()
	if runtime == nil {
		logEvent(logger, "managed_runtime", "run.skipped", field("reason", "runtime_unavailable"))
		return nil
	}
	if err := runtime.Run(); err != nil {
		logEvent(logger, "managed_runtime", "run.failed",
			field("error", err),
			durationField("duration", time.Since(started)),
		)
		return err
	}
	logEvent(logger, "managed_runtime", "run.success", durationField("duration", time.Since(started)))
	return nil
}

func (m *managedRuntime) Close() error {
	logger := m.opts.Logger
	started := time.Now()
	logEvent(logger, "managed_runtime", "close.begin")
	m.mu.Lock()
	runtime := m.runtime
	m.mu.Unlock()
	if runtime == nil {
		logEvent(logger, "managed_runtime", "close.skipped", field("reason", "runtime_unavailable"))
		return nil
	}
	err := runtime.Close()
	m.mu.Lock()
	m.refreshStatusLocked(runtime)
	m.status.Running = false
	status := m.status
	m.mu.Unlock()
	if err != nil {
		logEvent(logger, "managed_runtime", "close.failed",
			field("error", err),
			field("endpoint", status.Endpoint),
			durationField("duration", time.Since(started)),
		)
		return err
	}
	logEvent(logger, "managed_runtime", "close.success",
		field("endpoint", status.Endpoint),
		field("listen_address", status.ListenAddress),
		field("running", status.Running),
		durationField("duration", time.Since(started)),
	)
	return err
}

func (m *managedRuntime) runRuntimeHealthCheck(endpoint string, runtime sdkRuntime) error {
	if runtime == nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	return runtime.HealthCheck(ctx)
}

func (m *managedRuntime) reportEndpointFailure(endpoint string, err error) {
	if err == nil {
		return
	}
	m.mu.Lock()
	if m.switching || !m.status.Running || strings.TrimSpace(endpoint) == "" || endpoint != m.endpoint {
		m.mu.Unlock()
		return
	}
	if m.activeIdx+1 >= len(m.selection.Candidates) {
		m.mu.Unlock()
		return
	}
	selection := m.selection
	state := m.lastState
	runtime := m.runtime
	logger := m.opts.Logger
	m.switching = true
	m.mu.Unlock()

	logEvent(logger, "managed_runtime", "runtime.failover.begin",
		field("endpoint", endpoint),
		field("error", err),
	)

	go m.failoverRuntime(endpoint, err, selection, state, runtime)
}

func (m *managedRuntime) failoverRuntime(failedEndpoint string, triggerErr error, selection endpointSelection, state storage.State, current sdkRuntime) {
	logger := m.opts.Logger
	if current != nil {
		if err := current.Close(); err != nil {
			logEvent(logger, "managed_runtime", "runtime.close.failed",
				field("endpoint", failedEndpoint),
				field("error", err),
			)
		}
	}

	var endpointErrors []error
	for idx := m.nextCandidateIndex(selection, failedEndpoint); idx < len(selection.Candidates); idx++ {
		candidate := selection.Candidates[idx]
		logEvent(logger, "managed_runtime", "endpoint.failover",
			field("failed_endpoint", failedEndpoint),
			field("next_endpoint", candidate.Address),
			field("attempt", idx+1),
			field("total", len(selection.Candidates)),
		)

		runtime, err := m.buildFn(candidate.Address, state)
		if err != nil {
			endpointErrors = append(endpointErrors, fmt.Errorf("%s build failed: %w", candidate.Address, err))
			logEvent(logger, "managed_runtime", "runtime.build.failed",
				field("endpoint", candidate.Address),
				field("error", err),
			)
			continue
		}
		if m.tryHotSwapRuntime(current, runtime, candidate.Address, state, selection, idx, triggerErr) {
			return
		}
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		startErr := runtime.Start(ctx)
		cancel()
		if startErr != nil {
			endpointErrors = append(endpointErrors, fmt.Errorf("%s start failed: %w", candidate.Address, startErr))
			logEvent(logger, "managed_runtime", "runtime.start.failed",
				field("endpoint", candidate.Address),
				field("error", startErr),
			)
			_ = runtime.Close()
			continue
		}
		if current != nil {
			if err := current.Close(); err != nil {
				logEvent(logger, "managed_runtime", "runtime.close.failed",
					field("endpoint", failedEndpoint),
					field("error", err),
				)
			}
			current = nil
		}
		if healthErr := m.runRuntimeHealthCheck(candidate.Address, runtime); healthErr != nil {
			endpointErrors = append(endpointErrors, fmt.Errorf("%s health check failed: %w", candidate.Address, healthErr))
			logEvent(logger, "managed_runtime", "runtime.health.failed",
				field("endpoint", candidate.Address),
				field("error", healthErr),
			)
			_ = runtime.Close()
			continue
		}

		persistedState := state
		persistedState.SelectedNode = candidate.Address
		if saveErr := m.store.Save(persistedState); saveErr != nil {
			logEvent(logger, "managed_runtime", "state.save.failed",
				field("selected_node", persistedState.SelectedNode),
				field("error", saveErr),
			)
			_ = runtime.Close()
			endpointErrors = append(endpointErrors, fmt.Errorf("%s save failed: %w", candidate.Address, saveErr))
			continue
		}

		m.mu.Lock()
		m.runtime = runtime
		m.endpoint = candidate.Address
		m.selection = selection
		m.activeIdx = idx
		m.lastState = persistedState
		m.switching = false
		m.registered = true
		m.refreshStatusLocked(runtime)
		m.mu.Unlock()
		logEvent(logger, "managed_runtime", "runtime.failover.success",
			field("endpoint", candidate.Address),
			field("trigger_error", triggerErr),
		)
		return
	}

	m.mu.Lock()
	m.runtime = nil
	m.status.Running = false
	m.switching = false
	m.mu.Unlock()
	logEvent(logger, "managed_runtime", "runtime.failover.failed",
		field("endpoint", failedEndpoint),
		field("error", errors.Join(endpointErrors...)),
	)
}

func (m *managedRuntime) nextCandidateIndex(selection endpointSelection, failedEndpoint string) int {
	address := strings.TrimSpace(failedEndpoint)
	for idx, candidate := range selection.Candidates {
		if strings.TrimSpace(candidate.Address) == address {
			return idx + 1
		}
	}
	return 0
}

func (m *managedRuntime) tryHotSwapRuntime(current sdkRuntime, next sdkRuntime, endpoint string, state storage.State, selection endpointSelection, idx int, triggerErr error) bool {
	currentAdapter, okCurrent := current.(*runtimeAdapter)
	nextAdapter, okNext := next.(*runtimeAdapter)
	if !okCurrent || !okNext || currentAdapter == nil || nextAdapter == nil || currentAdapter.runtime == nil || nextAdapter.runtime == nil {
		return false
	}
	if !currentAdapter.runtime.HotSwapProxyBackendsFrom(nextAdapter.runtime) {
		return false
	}
	persistedState := state
	persistedState.SelectedNode = endpoint
	if saveErr := m.store.Save(persistedState); saveErr != nil {
		logEvent(m.opts.Logger, "managed_runtime", "state.save.failed",
			field("selected_node", persistedState.SelectedNode),
			field("error", saveErr),
		)
		return false
	}
	m.mu.Lock()
	m.runtime = current
	m.endpoint = endpoint
	m.selection = selection
	m.activeIdx = idx
	m.lastState = persistedState
	m.switching = false
	m.registered = true
	m.refreshStatusLocked(current)
	m.mu.Unlock()
	logEvent(m.opts.Logger, "managed_runtime", "runtime.failover.success",
		field("endpoint", endpoint),
		field("hot_swap", true),
		field("trigger_error", triggerErr),
	)
	return true
}

func (m *managedRuntime) Status() Status {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.status
}

func (m *managedRuntime) HealthCheck(ctx context.Context) error {
	m.mu.Lock()
	runtime := m.runtime
	m.mu.Unlock()
	if runtime == nil {
		return nil
	}
	return runtime.HealthCheck(ctx)
}

func (m *managedRuntime) ListenAddress() string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.status.ListenAddress
}

func (m *managedRuntime) refreshStatusLocked(runtime sdkRuntime) {
	if runtime == nil {
		return
	}
	rtStatus := runtime.Status()
	m.status.Running = rtStatus.Running
	m.status.ListenAddress = rtStatus.ListenAddress
	m.status.HTTPEnabled = rtStatus.HTTPEnabled
	m.status.SOCKS5Enabled = rtStatus.SOCKS5Enabled
	m.status.TUNEnabled = rtStatus.TUNEnabled
	m.status.Endpoint = m.endpoint
	m.status.Registered = m.registered
}

func (m *managedRuntime) newCandidateChecker(state storage.State) discovery.WarpStatusChecker {
	if m.opts.TUN.Enabled && !m.opts.HTTP.Enabled && !m.opts.SOCKS5.Enabled {
		return discovery.WarpStatusFunc(func(ctx context.Context, candidate discovery.Candidate) (bool, error) {
			done := make(chan error, 1)
			go func() {
				done <- validateTUNCandidateForSelection(ctx, m.opts, state, candidate)
			}()
			select {
			case <-ctx.Done():
				return false, context.Cause(ctx)
			case err := <-done:
				if err != nil {
					return false, err
				}
				return true, nil
			}
		})
	}
	return discovery.WarpStatusFunc(func(ctx context.Context, candidate discovery.Candidate) (bool, error) {
		kernelCfg := baseKernelConfigFromState(state, candidate.Address, strings.TrimSpace(m.opts.Transport.SNI), amzconfig.ModeHTTP, m.opts.Listen.Address, withAction(m.opts.Logger, "SELECT"))
		connectionManager, err := amzsession.NewConnectionManager(kernelCfg)
		if err != nil {
			return false, err
		}
		defer connectionManager.Close()
		if err := connectionManager.Connect(ctx); err != nil {
			return false, err
		}
		return connectionManager.Snapshot().State == amzsession.ConnStateReady, nil
	})
}

func (m *managedRuntime) selectEndpoint(ctx context.Context, state storage.State) (endpointSelection, []storage.Node, error) {
	if endpoint := strings.TrimSpace(m.opts.Transport.Endpoint); endpoint != "" {
		candidate := discovery.Candidate{
			Address:     endpoint,
			Source:      discovery.SourceFixed,
			Available:   true,
			WarpEnabled: true,
		}
		return newEndpointSelection(candidate, []discovery.Candidate{candidate}), state.NodeCache, nil
	}

	ipv6Supported := detectIPv6Support()
	input := buildDiscoveryInput(state, ipv6Supported)

	preferredCandidates, fallbackCandidates := discovery.BuildVerificationCandidates(input, 443, 4)
	preferredCandidates = filterCandidatesByIPv6Support(preferredCandidates, ipv6Supported)
	fallbackCandidates = filterCandidatesByIPv6Support(fallbackCandidates, ipv6Supported)
	if m.opts.TUN.Enabled && !m.opts.HTTP.Enabled && !m.opts.SOCKS5.Enabled {
		preferredCandidates = prioritizeTUNCandidates(preferredCandidates)
		fallbackCandidates = prioritizeTUNCandidates(fallbackCandidates)
	}
	logEvent(m.opts.Logger, "managed_runtime", "endpoint.plan.ready",
		field("preferred_count", len(preferredCandidates)),
		field("fallback_count", len(fallbackCandidates)),
		field("total_count", len(mergeUniqueCandidates(preferredCandidates, fallbackCandidates))),
		field("ipv6_supported", ipv6Supported),
	)

	checker := m.newCandidateChecker(state)
	profile := defaultProbeProfile
	if m.opts.TUN.Enabled && !m.opts.HTTP.Enabled && !m.opts.SOCKS5.Enabled {
		profile = tunProbeProfile
	}
	logEvent(m.opts.Logger, "managed_runtime", "endpoint.probe_profile",
		field("probe_profile", profile.name),
		field("per_candidate_timeout", profile.perCandidateTimeout),
		field("batch_timeout", profile.batchTimeout),
		field("concurrency", profile.concurrency),
	)
	prober := discovery.NewRealProber(profile.perCandidateTimeout,
		discovery.WithWarpStatusChecker(checker),
		discovery.WithProbeObserver(newLoggingProbeObserver(m.opts.Logger)),
		discovery.WithProbeConcurrency(profile.concurrency),
		discovery.WithProbeBatchTimeout(profile.batchTimeout),
	)

	result := discovery.BatchProbe(prober, prepareCandidatesForProbe(mergeUniqueCandidates(preferredCandidates, fallbackCandidates)))
	if !result.OK {
		return endpointSelection{}, state.NodeCache, fmt.Errorf("no available warp candidate")
	}
	return newEndpointSelection(result.Best, discovery.AvailableCandidates(result.Ranked)), state.NodeCache, nil
}

func (m *managedRuntime) buildRuntime(endpoint string, state storage.State) (sdkRuntime, error) {
	var httpRT *iruntime.HTTPRuntime
	var socksRT *iruntime.SOCKS5Runtime
	var tunRT *iruntime.TUNRuntime

	if m.opts.HTTP.Enabled || m.opts.SOCKS5.Enabled {
		baseCfg := baseKernelConfigFromState(state, endpoint, strings.TrimSpace(m.opts.Transport.SNI), amzconfig.ModeHTTP, m.opts.Listen.Address, withAction(m.opts.Logger, "PROXY"))
		connectionManager, err := amzsession.NewConnectionManager(baseCfg)
		if err != nil {
			return nil, err
		}
		connectIPManager, err := amzsession.NewConnectIPSessionManager(baseCfg)
		if err != nil {
			return nil, err
		}
		connectIPManager.UpdateSessionInfo(sessionInfoFromState(state))
		delegate := &net.Dialer{Timeout: baseCfg.ConnectTimeout}

		// Create one shared BootstrapDialer and PacketStackDialer for both HTTP and SOCKS5
		sharedDialer, err := amzsession.NewBootstrapDialer(connectionManager, connectIPManager, delegate)
		if err != nil {
			return nil, err
		}
		sharedDialer.SetFailureReporter(func(err error) {
			m.reportEndpointFailure(endpoint, err)
		})
		sharedPacketDialer, err := amzsession.NewPacketStackDialer(sharedDialer)
		if err != nil {
			return nil, err
		}
		sharedDNSDialer := iruntime.NewExportedDNSResolvingDialer(sharedPacketDialer)

		if m.opts.HTTP.Enabled {
			httpCfg := baseCfg
			httpCfg.Mode = amzconfig.ModeHTTP
			httpCfg.HTTP.ListenAddress = m.opts.Listen.Address
			runtime, err := iruntime.NewHTTPRuntimeFromSharedDialer(httpCfg, sharedDNSDialer, amzsession.NewPreparedProxyStreamOpener(sharedDialer, sharedDialer.StreamManager()))
			if err != nil {
				return nil, err
			}
			runtime.SetFailureReporter(func(err error) {
				m.reportEndpointFailure(endpoint, err)
			})
			httpRT = runtime
		}

		if m.opts.SOCKS5.Enabled {
			socksCfg := baseCfg
			socksCfg.Mode = amzconfig.ModeSOCKS
			socksCfg.SOCKS.ListenAddress = m.opts.Listen.Address
			runtime, err := iruntime.NewSOCKS5RuntimeFromSharedDialer(&socksCfg, sharedDNSDialer)
			if err != nil {
				return nil, err
			}
			runtime.SetFailureReporter(func(err error) {
				m.reportEndpointFailure(endpoint, err)
			})
			socksRT = runtime
		}
	}

	if m.opts.TUN.Enabled {
		tunCfg := baseKernelConfigFromState(state, endpoint, strings.TrimSpace(m.opts.Transport.SNI), amzconfig.ModeTUN, "", withAction(m.opts.Logger, "TUN"))
		connectionManager, err := amzsession.NewConnectionManager(tunCfg)
		if err != nil {
			return nil, err
		}
		connectIPManager, err := amzsession.NewConnectIPSessionManager(tunCfg)
		if err != nil {
			return nil, err
		}
		connectIPManager.UpdateSessionInfo(sessionInfoFromState(state))
		bootstrap, err := amzsession.NewBootstrapDialer(connectionManager, connectIPManager, &net.Dialer{Timeout: tunCfg.ConnectTimeout})
		if err != nil {
			return nil, err
		}
		bootstrap.SetFailureReporter(func(err error) {
			m.reportEndpointFailure(endpoint, err)
		})
		manager, err := iruntime.NewBootstrapTUNManager(&tunCfg, bootstrap)
		if err != nil {
			return nil, err
		}
		tunRT = iruntime.NewTUNRuntimeWithHealth(manager, bootstrap.HealthCheck)
	}

	runtime, err := iruntime.NewClientRuntime(iruntime.ClientRuntimeOptions{
		ListenAddress: m.opts.Listen.Address,
		HTTP:          httpRT,
		SOCKS5:        socksRT,
		TUN:           tunRT,
	})
	if err != nil {
		return nil, err
	}
	return &runtimeAdapter{runtime: runtime}, nil
}

type runtimeAdapter struct {
	runtime *iruntime.ClientRuntime
}

func (r *runtimeAdapter) Start(ctx context.Context) error { return r.runtime.Start(ctx) }
func (r *runtimeAdapter) Run() error                      { return r.runtime.Run() }
func (r *runtimeAdapter) Close() error                    { return r.runtime.Close() }
func (r *runtimeAdapter) HealthCheck(ctx context.Context) error {
	if r == nil || r.runtime == nil {
		return nil
	}
	return r.runtime.HealthCheck(ctx)
}
func (r *runtimeAdapter) ListenAddress() string { return r.runtime.ListenAddress() }

func (r *runtimeAdapter) Status() Status {
	if r == nil || r.runtime == nil {
		return Status{}
	}
	status := r.runtime.Status()
	return Status{
		Running:       status.Running,
		ListenAddress: status.ListenAddress,
		HTTPEnabled:   status.HTTPEnabled,
		SOCKS5Enabled: status.SOCKS5Enabled,
		TUNEnabled:    status.TUNEnabled,
	}
}

func baseKernelConfigFromState(state storage.State, endpoint, sni, mode, listen string, logger Logger) amzconfig.KernelConfig {
	cfg := amzconfig.KernelConfig{
		Endpoint: endpoint,
		SNI:      amzconfig.DefaultSNI,
		Mode:     mode,
		Logger:   logger,
		TLS: amzconfig.TLSConfig{
			ClientPrivateKey:  state.Certificate.PrivateKey,
			ClientCertificate: state.Certificate.ClientCertificate,
			PeerPublicKey:     state.Certificate.PeerPublicKey,
			ClientID:          state.Certificate.ClientID,
		},
	}
	if strings.TrimSpace(sni) != "" {
		cfg.SNI = strings.TrimSpace(sni)
	}
	switch mode {
	case amzconfig.ModeHTTP:
		cfg.HTTP.ListenAddress = listen
		// Free accounts don't support upstream proxy; use PacketStack direct dialer instead
		// cfg.HTTP.UpstreamAddress = strings.TrimSpace(state.Services.HTTPProxy)
	case amzconfig.ModeSOCKS:
		cfg.SOCKS.ListenAddress = listen
	case amzconfig.ModeTUN:
		cfg.TUN.Name = "amz0"
	}
	cfg.FillDefaults()
	return cfg
}

func registrationFromState(state storage.State) discovery.Registration {
	node := selectRegistrationNode(state)
	return discovery.Registration{
		EndpointV4:    node.EndpointV4,
		EndpointV6:    node.EndpointV6,
		EndpointHost:  node.Host,
		EndpointPorts: append([]uint16(nil), node.Ports...),
	}
}

func cacheFromState(state storage.State) discovery.Cache {
	candidates := make([]discovery.Candidate, 0)
	var selected discovery.Candidate
	for _, node := range state.NodeCache {
		addresses := nodeCandidateAddresses(node)
		for _, address := range addresses {
			candidate := discovery.Candidate{
				Address:     address,
				Source:      discovery.SourceFixed,
				Available:   true,
				WarpEnabled: true,
			}
			candidates = append(candidates, candidate)
			if state.SelectedNode != "" && (state.SelectedNode == node.ID || state.SelectedNode == address) && selected.Address == "" {
				selected = candidate
			}
		}
	}
	if selected.Address == "" && state.SelectedNode != "" {
		selected = discovery.Candidate{
			Address:     state.SelectedNode,
			Source:      discovery.SourceFixed,
			Available:   true,
			WarpEnabled: true,
		}
	}
	return discovery.Cache{
		Selected:   selected,
		Candidates: candidates,
	}
}

func selectRegistrationNode(state storage.State) storage.Node {
	for _, node := range state.NodeCache {
		if state.SelectedNode != "" && state.SelectedNode == node.ID {
			return node
		}
	}
	if len(state.NodeCache) > 0 {
		return state.NodeCache[0]
	}
	return storage.Node{}
}

func nodeCandidateAddresses(node storage.Node) []string {
	addresses := make([]string, 0)
	appendHostWithPorts := func(host string, ports []uint16) {
		host = strings.TrimSpace(host)
		if host == "" {
			return
		}
		if parsedHost, _, err := net.SplitHostPort(host); err == nil {
			host = parsedHost
		}
		if len(ports) == 0 {
			addresses = append(addresses, net.JoinHostPort(host, "443"))
			return
		}
		for _, port := range ports {
			addresses = append(addresses, net.JoinHostPort(host, strconv.Itoa(int(port))))
		}
	}
	appendRawEndpoint := func(endpoint string, ports []uint16) {
		endpoint = strings.TrimSpace(endpoint)
		if endpoint == "" {
			return
		}
		if host, _, err := net.SplitHostPort(endpoint); err == nil {
			appendHostWithPorts(host, ports)
			return
		}
		addresses = append(addresses, endpoint)
	}
	appendHostWithPorts(node.Host, node.Ports)
	appendRawEndpoint(node.EndpointV4, node.Ports)
	appendRawEndpoint(node.EndpointV6, node.Ports)
	return dedupeStrings(addresses)
}

func dedupeStrings(items []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(items))
	for _, item := range items {
		item = strings.TrimSpace(item)
		if item == "" || seen[item] {
			continue
		}
		seen[item] = true
		out = append(out, item)
	}
	return out
}

func sessionInfoFromState(state storage.State) amzsession.SessionInfo {
	info := amzsession.SessionInfo{}
	if strings.TrimSpace(state.Interface.V4) != "" {
		info.IPv4 = strings.TrimSpace(state.Interface.V4) + "/32"
		info.Routes = append(info.Routes, "0.0.0.0/0")
	}
	if strings.TrimSpace(state.Interface.V6) != "" {
		info.IPv6 = strings.TrimSpace(state.Interface.V6) + "/128"
		info.Routes = append(info.Routes, "::/0")
	}
	return info
}

func newEndpointSelection(primary discovery.Candidate, candidates []discovery.Candidate) endpointSelection {
	ordered := make([]discovery.Candidate, 0, len(candidates)+1)
	seen := make(map[string]bool, len(candidates)+1)
	appendCandidate := func(candidate discovery.Candidate) {
		address := strings.TrimSpace(candidate.Address)
		if address == "" || seen[address] {
			return
		}
		seen[address] = true
		candidate.Address = address
		ordered = append(ordered, candidate)
	}

	appendCandidate(primary)
	for _, candidate := range candidates {
		appendCandidate(candidate)
	}
	if strings.TrimSpace(primary.Address) == "" && len(ordered) > 0 {
		primary = ordered[0]
	}
	return endpointSelection{
		Primary:    primary,
		Candidates: ordered,
	}
}

type authEnsurer interface {
	Ensure(context.Context) (auth.Result, error)
}

type stateStore interface {
	Load() (storage.State, error)
	Save(state storage.State) error
}

var newDefaultAuthService = auth.NewDefaultService

func prepareCandidatesForProbe(candidates []discovery.Candidate) []discovery.Candidate {
	prepared := make([]discovery.Candidate, 0, len(candidates))
	for _, candidate := range candidates {
		candidate.Available = false
		candidate.WarpEnabled = false
		candidate.Latency = 0
		candidate.Reason = "not_probed"
		prepared = append(prepared, candidate)
	}
	return prepared
}

func prioritizeTUNCandidates(candidates []discovery.Candidate) []discovery.Candidate {
	prioritized := append([]discovery.Candidate(nil), candidates...)
	sort.SliceStable(prioritized, func(i, j int) bool {
		left := tunCandidatePriority(prioritized[i].Address, prioritized[i].Source)
		right := tunCandidatePriority(prioritized[j].Address, prioritized[j].Source)
		return left < right
	})
	return prioritized
}

func tunCandidatePriority(address, source string) int {
	host, port, err := net.SplitHostPort(strings.TrimSpace(address))
	if err != nil {
		host = strings.TrimSpace(address)
		port = ""
	}
	host = strings.Trim(host, "[]")

	hostRank := 100
	switch host {
	case "162.159.198.2":
		hostRank = 0
	case "162.159.198.1":
		hostRank = 10
	case "engage.cloudflareclient.com":
		hostRank = 20
	default:
		if strings.TrimSpace(source) == discovery.SourceAuto {
			hostRank = 30
		}
	}

	portRank := 100
	switch port {
	case "4500":
		portRank = 0
	case "500":
		portRank = 1
	case "1701":
		portRank = 2
	case "443":
		portRank = 3
	case "8443":
		portRank = 4
	case "8095":
		portRank = 5
	case "4443":
		portRank = 6
	}

	return hostRank*10 + portRank
}
