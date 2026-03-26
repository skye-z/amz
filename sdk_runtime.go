package amz

import (
	"context"
	"fmt"
	"net"
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
	selectFn   func(context.Context, storage.State) (discovery.Candidate, []storage.Node, error)
	buildFn    func(string, storage.State) (sdkRuntime, error)
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
	return runtime, nil
}

func (m *managedRuntime) Start(ctx context.Context) error {
	m.mu.Lock()
	if m.runtime != nil {
		runtime := m.runtime
		m.mu.Unlock()
		if err := runtime.Start(ctx); err != nil {
			return err
		}
		m.refreshStatusLocked(runtime)
		return nil
	}
	m.mu.Unlock()

	authResult, err := m.auth.Ensure(ctx)
	if err != nil {
		return err
	}

	state := authResult.State
	candidate, cache, err := m.selectFn(ctx, state)
	if err != nil {
		return err
	}
	state.SelectedNode = candidate.Address
	state.NodeCache = cache
	if saveErr := m.store.Save(state); saveErr != nil {
		return saveErr
	}

	runtime, err := m.buildFn(candidate.Address, state)
	if err != nil {
		return err
	}
	if err := runtime.Start(ctx); err != nil {
		return err
	}

	m.mu.Lock()
	m.runtime = runtime
	m.registered = true
	m.endpoint = candidate.Address
	m.refreshStatusLocked(runtime)
	m.mu.Unlock()
	return nil
}

func (m *managedRuntime) Run() error {
	if err := m.Start(context.Background()); err != nil {
		return err
	}

	m.mu.Lock()
	runtime := m.runtime
	m.mu.Unlock()
	if runtime == nil {
		return nil
	}
	return runtime.Run()
}

func (m *managedRuntime) Close() error {
	m.mu.Lock()
	runtime := m.runtime
	m.mu.Unlock()
	if runtime == nil {
		return nil
	}
	err := runtime.Close()
	m.mu.Lock()
	m.refreshStatusLocked(runtime)
	m.status.Running = false
	m.mu.Unlock()
	return err
}

func (m *managedRuntime) Status() Status {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.status
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

func (m *managedRuntime) selectEndpoint(ctx context.Context, state storage.State) (discovery.Candidate, []storage.Node, error) {
	if endpoint := strings.TrimSpace(m.opts.Transport.Endpoint); endpoint != "" {
		candidate := discovery.Candidate{
			Address:     endpoint,
			Source:      discovery.SourceFixed,
			Available:   true,
			WarpEnabled: true,
		}
		return candidate, state.NodeCache, nil
	}

	input := discovery.Input{
		Registration: registrationFromState(state),
		Cache:        cacheFromState(state),
		Scan: discovery.Scan{
			Source: "auto",
			Range4: []string{"162.159.192.0/24"},
			Range6: []string{"2606:4700:103::/64"},
		},
	}

	prober := discovery.NewRealProber(10*time.Second, discovery.WithWarpStatusChecker(discovery.WarpStatusFunc(func(ctx context.Context, candidate discovery.Candidate) (bool, error) {
		kernelCfg := baseKernelConfigFromState(state, candidate.Address, strings.TrimSpace(m.opts.Transport.SNI), amzconfig.ModeHTTP, m.opts.Listen.Address)
		connectionManager, err := amzsession.NewConnectionManager(kernelCfg)
		if err != nil {
			return false, err
		}
		defer connectionManager.Close()
		if err := connectionManager.Connect(ctx); err != nil {
			return false, err
		}
		return connectionManager.Snapshot().State == amzsession.ConnStateReady, nil
	})))

	result := discovery.Select(input, prober, 443, 4)
	if !result.OK {
		return discovery.Candidate{}, state.NodeCache, fmt.Errorf("no available warp candidate")
	}
	return result.Best, state.NodeCache, nil
}

func (m *managedRuntime) buildRuntime(endpoint string, state storage.State) (sdkRuntime, error) {
	var httpRT *iruntime.HTTPRuntime
	var socksRT *iruntime.SOCKS5Runtime
	var tunRT *iruntime.TUNRuntime

	if m.opts.HTTP.Enabled || m.opts.SOCKS5.Enabled {
		baseCfg := baseKernelConfigFromState(state, endpoint, strings.TrimSpace(m.opts.Transport.SNI), amzconfig.ModeHTTP, m.opts.Listen.Address)
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
		sharedPacketDialer, err := amzsession.NewPacketStackDialer(sharedDialer)
		if err != nil {
			return nil, err
		}
		sharedDNSDialer := iruntime.NewExportedDNSResolvingDialer(sharedPacketDialer)

		if m.opts.HTTP.Enabled {
			httpCfg := baseCfg
			httpCfg.Mode = amzconfig.ModeHTTP
			httpCfg.HTTP.ListenAddress = m.opts.Listen.Address
			runtime, err := iruntime.NewHTTPRuntimeFromSharedDialer(httpCfg, sharedDNSDialer)
			if err != nil {
				return nil, err
			}
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
			socksRT = runtime
		}
	}

	if m.opts.TUN.Enabled {
		tunCfg := baseKernelConfigFromState(state, endpoint, strings.TrimSpace(m.opts.Transport.SNI), amzconfig.ModeTUN, "")
		runtime, err := iruntime.NewTUNRuntimeFromConfig(&tunCfg)
		if err != nil {
			return nil, err
		}
		tunRT = runtime
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
func (r *runtimeAdapter) ListenAddress() string           { return r.runtime.ListenAddress() }

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

func baseKernelConfigFromState(state storage.State, endpoint, sni, mode, listen string) amzconfig.KernelConfig {
	cfg := amzconfig.KernelConfig{
		Endpoint: endpoint,
		SNI:      amzconfig.DefaultSNI,
		Mode:     mode,
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

type authEnsurer interface {
	Ensure(context.Context) (auth.Result, error)
}

type stateStore interface {
	Load() (storage.State, error)
	Save(state storage.State) error
}

var newDefaultAuthService = auth.NewDefaultService
