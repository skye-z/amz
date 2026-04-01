package discovery

import (
	"context"
	"fmt"
	"net"
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	// DefaultProbePort is the default port used when expanding probe candidates.
	DefaultProbePort = 443
	// DefaultProbeSampleLimit is the default number of CIDR samples.
	DefaultProbeSampleLimit = 4
	// DefaultProbeTimeout is the default timeout for a single candidate probe.
	DefaultProbeTimeout = 750 * time.Millisecond
)

type staticProber struct {
	results map[string]ProbeResult
}

// ProbeDialer abstracts the minimal dial ability needed for probing.
type ProbeDialer interface {
	DialContext(ctx context.Context, network, address string) (net.Conn, error)
}

// DialContextFunc adapts a function into a ProbeDialer.
type DialContextFunc func(ctx context.Context, network, address string) (net.Conn, error)

func (f DialContextFunc) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	return f(ctx, network, address)
}

// WarpStatusChecker checks whether a candidate can establish a usable WARP session.
type WarpStatusChecker interface {
	CheckWarp(ctx context.Context, candidate Candidate) (bool, error)
}

// WarpStatusFunc adapts a function into a WarpStatusChecker.
type WarpStatusFunc func(ctx context.Context, candidate Candidate) (bool, error)

func (f WarpStatusFunc) CheckWarp(ctx context.Context, candidate Candidate) (bool, error) {
	return f(ctx, candidate)
}

// ProbeObserver observes per-candidate probing progress.
type ProbeObserver interface {
	OnProbeStart(candidate Candidate, index, total int)
	OnProbeDone(candidate Candidate, result ProbeResult, duration time.Duration, index, total int)
	OnWarpCheckStart(candidate Candidate)
	OnWarpCheckDone(candidate Candidate, ok bool, err error, duration time.Duration)
}

// RealProber probes candidates against the network.
type RealProber struct {
	timeout      time.Duration
	batchTimeout time.Duration
	concurrency  int
	network      string
	dialer       ProbeDialer
	checker      WarpStatusChecker
	observer     ProbeObserver
}

// RealProberOption configures a RealProber.
type RealProberOption func(*RealProber)

// WithProbeDialer provides a custom dialer.
func WithProbeDialer(dialer ProbeDialer) RealProberOption {
	return func(p *RealProber) {
		if dialer != nil {
			p.dialer = dialer
		}
	}
}

// WithWarpStatusChecker provides a custom warp status checker.
func WithWarpStatusChecker(checker WarpStatusChecker) RealProberOption {
	return func(p *RealProber) {
		if checker != nil {
			p.checker = checker
		}
	}
}

// WithProbeNetwork overrides the probe network type.
func WithProbeNetwork(network string) RealProberOption {
	return func(p *RealProber) {
		if trimmed := strings.TrimSpace(network); trimmed != "" {
			p.network = trimmed
		}
	}
}

// WithProbeConcurrency sets how many candidates can be probed concurrently.
func WithProbeConcurrency(concurrency int) RealProberOption {
	return func(p *RealProber) {
		if concurrency > 0 {
			p.concurrency = concurrency
		}
	}
}

// WithProbeBatchTimeout sets a deadline for the whole batch probing flow.
func WithProbeBatchTimeout(timeout time.Duration) RealProberOption {
	return func(p *RealProber) {
		if timeout > 0 {
			p.batchTimeout = timeout
		}
	}
}

// WithProbeObserver attaches a probe observer.
func WithProbeObserver(observer ProbeObserver) RealProberOption {
	return func(p *RealProber) {
		if observer != nil {
			p.observer = observer
		}
	}
}

// NewStaticProber creates a prober with fixed results.
func NewStaticProber(results map[string]ProbeResult) Prober {
	clone := make(map[string]ProbeResult, len(results))
	for key, value := range results {
		clone[key] = value
	}
	return &staticProber{results: clone}
}

func (s *staticProber) Probe(candidates []Candidate) []ProbeResult {
	results := make([]ProbeResult, 0, len(candidates))
	for _, candidate := range candidates {
		if result, ok := s.results[candidate.Address]; ok {
			results = append(results, result)
		}
	}
	return results
}

// NewRealProber creates a real network prober.
func NewRealProber(timeout time.Duration, options ...RealProberOption) *RealProber {
	if timeout <= 0 {
		timeout = DefaultProbeTimeout
	}
	prober := &RealProber{
		timeout:     timeout,
		concurrency: 1,
		network:     "tcp",
		dialer:      &net.Dialer{Timeout: timeout},
	}
	for _, option := range options {
		if option != nil {
			option(prober)
		}
	}
	return prober
}

// Probe probes candidates, respecting concurrency and optional batch timeout.
func (p *RealProber) Probe(candidates []Candidate) []ProbeResult {
	if len(candidates) == 0 {
		return nil
	}

	workerCount := p.concurrency
	if workerCount <= 0 {
		workerCount = 1
	}
	if workerCount > len(candidates) {
		workerCount = len(candidates)
	}

	batchCtx := context.Background()
	cancel := func() {
		// No-op when no timeout context was created.
	}
	if p.batchTimeout > 0 {
		batchCtx, cancel = context.WithTimeout(batchCtx, p.batchTimeout)
	}
	defer cancel()

	type probeTask struct {
		index     int
		total     int
		candidate Candidate
	}
	type indexedResult struct {
		index  int
		result ProbeResult
	}

	jobs := make(chan probeTask)
	resultsCh := make(chan indexedResult, len(candidates))

	var wg sync.WaitGroup
	for range workerCount {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for task := range jobs {
				result := p.probeCandidate(batchCtx, task.candidate, task.index, task.total)
				resultsCh <- indexedResult{index: task.index, result: result}
			}
		}()
	}

	go func() {
		defer close(jobs)
		for idx, candidate := range candidates {
			select {
			case <-batchCtx.Done():
				return
			case jobs <- probeTask{index: idx, total: len(candidates), candidate: candidate}:
			}
		}
	}()

	go func() {
		wg.Wait()
		close(resultsCh)
	}()

	indexed := make([]indexedResult, 0, len(candidates))
	for result := range resultsCh {
		indexed = append(indexed, result)
	}
	sort.Slice(indexed, func(i, j int) bool { return indexed[i].index < indexed[j].index })

	results := make([]ProbeResult, 0, len(indexed))
	for _, item := range indexed {
		results = append(results, item.result)
	}
	return results
}

func (p *RealProber) probeCandidate(batchCtx context.Context, candidate Candidate, index, total int) ProbeResult {
	result := ProbeResult{Address: candidate.Address}
	if strings.TrimSpace(candidate.Address) == "" {
		return result
	}

	if p.observer != nil {
		p.observer.OnProbeStart(candidate, index+1, total)
	}
	started := time.Now()

	ctx := batchCtx
	cancel := func() {
		// No-op when no timeout context was created.
	}
	if p.timeout > 0 {
		ctx, cancel = context.WithTimeout(batchCtx, p.timeout)
	}
	defer cancel()

	network := p.probeNetwork(candidate)
	conn, err := p.dialer.DialContext(ctx, network, candidate.Address)
	latency := time.Since(started)
	if err != nil {
		result.Reason = fmt.Sprintf("dial_failed: %v", err)
		if p.observer != nil {
			p.observer.OnProbeDone(candidate, result, time.Since(started), index+1, total)
		}
		return result
	}
	if conn != nil {
		_ = conn.Close()
	}
	if latency <= 0 {
		latency = time.Nanosecond
	}

	result.Latency = latency
	result.Available = true
	result.WarpEnabled = true
	if p.checker != nil {
		if p.observer != nil {
			p.observer.OnWarpCheckStart(candidate)
		}
		checkStarted := time.Now()
		warpEnabled, err := p.checker.CheckWarp(ctx, candidate)
		if p.observer != nil {
			p.observer.OnWarpCheckDone(candidate, warpEnabled, err, time.Since(checkStarted))
		}
		if err != nil {
			result.Available = false
			result.WarpEnabled = false
			result.Reason = fmt.Sprintf("warp_check_failed: %v", err)
			if p.observer != nil {
				p.observer.OnProbeDone(candidate, result, time.Since(started), index+1, total)
			}
			return result
		}
		result.Available = warpEnabled
		result.WarpEnabled = warpEnabled
		if !warpEnabled {
			result.Reason = "warp_check_failed: unavailable"
		}
	}
	if p.observer != nil {
		p.observer.OnProbeDone(candidate, result, time.Since(started), index+1, total)
	}
	return result
}

func (p *RealProber) probeNetwork(candidate Candidate) string {
	if strings.TrimSpace(p.network) != "" && p.network != "tcp" {
		return p.network
	}
	_, port, err := net.SplitHostPort(strings.TrimSpace(candidate.Address))
	if err != nil {
		return p.network
	}
	switch port {
	case "500", "1701", "4500":
		return "udp"
	default:
		return p.network
	}
}

// ApplyProbeResults merges probe results back into the candidate list.
func ApplyProbeResults(candidates []Candidate, results []ProbeResult) []Candidate {
	updated := append([]Candidate(nil), candidates...)
	indexByAddress := make(map[string]int, len(updated))
	for i, candidate := range updated {
		indexByAddress[candidate.Address] = i
	}
	for _, result := range results {
		index, ok := indexByAddress[result.Address]
		if !ok {
			continue
		}
		updated[index].Latency = result.Latency
		updated[index].Available = result.Available
		updated[index].WarpEnabled = result.WarpEnabled
		updated[index].Reason = result.Reason
	}
	return updated
}

// ProbeCandidates updates candidate status using the provided prober.
func ProbeCandidates(prober Prober, candidates []Candidate) []Candidate {
	if prober == nil {
		return append([]Candidate(nil), candidates...)
	}
	return ApplyProbeResults(candidates, prober.Probe(candidates))
}

// BatchProbe probes, ranks and picks the best candidate.
func BatchProbe(prober Prober, candidates []Candidate) BatchResult {
	updated := append([]Candidate(nil), candidates...)
	if prober != nil {
		updated = ProbeCandidates(prober, candidates)
	}
	ranked := RankCandidates(updated)
	best, ok := PickBestCandidate(updated)
	if prober == nil {
		ok = false
		best = Candidate{}
	}
	return BatchResult{
		Candidates: updated,
		Ranked:     ranked,
		Best:       best,
		OK:         ok,
	}
}

// BatchProbePlan expands a plan then probes it.
func BatchProbePlan(plan Plan, prober Prober, port, limit int) BatchResult {
	if port <= 0 {
		port = DefaultProbePort
	}
	if limit <= 0 {
		limit = DefaultProbeSampleLimit
	}
	return BatchProbe(prober, BuildCandidatesFromPlan(plan, port, limit))
}
