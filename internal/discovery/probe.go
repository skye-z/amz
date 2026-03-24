package discovery

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"
)

const (
	// DefaultProbePort 是默认探测端口。
	DefaultProbePort = 443
	// DefaultProbeSampleLimit 是默认 CIDR 样本数。
	DefaultProbeSampleLimit = 4
	// DefaultProbeTimeout 是默认探测超时。
	DefaultProbeTimeout = 750 * time.Millisecond
)

type staticProber struct {
	results map[string]ProbeResult
}

// ProbeDialer 抽象真实探测所需的最小拨号能力。
type ProbeDialer interface {
	DialContext(ctx context.Context, network, address string) (net.Conn, error)
}

// DialContextFunc 允许用函数注入 ProbeDialer。
type DialContextFunc func(ctx context.Context, network, address string) (net.Conn, error)

func (f DialContextFunc) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	return f(ctx, network, address)
}

// WarpStatusChecker 抽象 WARP 可用性判断逻辑。
type WarpStatusChecker interface {
	CheckWarp(ctx context.Context, candidate Candidate) (bool, error)
}

// WarpStatusFunc 允许用函数注入 WarpStatusChecker。
type WarpStatusFunc func(ctx context.Context, candidate Candidate) (bool, error)

func (f WarpStatusFunc) CheckWarp(ctx context.Context, candidate Candidate) (bool, error) {
	return f(ctx, candidate)
}

// RealProber 描述真实探测器。
type RealProber struct {
	timeout time.Duration
	network string
	dialer  ProbeDialer
	checker WarpStatusChecker
}

// RealProberOption 描述真实探测器选项。
type RealProberOption func(*RealProber)

// WithProbeDialer 指定自定义拨号器。
func WithProbeDialer(dialer ProbeDialer) RealProberOption {
	return func(p *RealProber) {
		if dialer != nil {
			p.dialer = dialer
		}
	}
}

// WithWarpStatusChecker 指定自定义 WARP 状态检查器。
func WithWarpStatusChecker(checker WarpStatusChecker) RealProberOption {
	return func(p *RealProber) {
		if checker != nil {
			p.checker = checker
		}
	}
}

// WithProbeNetwork 指定探测网络类型。
func WithProbeNetwork(network string) RealProberOption {
	return func(p *RealProber) {
		if trimmed := strings.TrimSpace(network); trimmed != "" {
			p.network = trimmed
		}
	}
}

// NewStaticProber 创建固定返回结果的探测器。
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

// NewRealProber 创建真实网络探测器。
func NewRealProber(timeout time.Duration, options ...RealProberOption) *RealProber {
	if timeout <= 0 {
		timeout = DefaultProbeTimeout
	}
	prober := &RealProber{
		timeout: timeout,
		network: "tcp",
		dialer:  &net.Dialer{Timeout: timeout},
	}
	for _, option := range options {
		if option != nil {
			option(prober)
		}
	}
	return prober
}

// Probe 逐个探测候选。
func (p *RealProber) Probe(candidates []Candidate) []ProbeResult {
	results := make([]ProbeResult, 0, len(candidates))
	for _, candidate := range candidates {
		results = append(results, p.probeCandidate(candidate))
	}
	return results
}

func (p *RealProber) probeCandidate(candidate Candidate) ProbeResult {
	result := ProbeResult{Address: candidate.Address}
	if strings.TrimSpace(candidate.Address) == "" {
		return result
	}

	ctx, cancel := context.WithTimeout(context.Background(), p.timeout)
	defer cancel()

	started := time.Now()
	network := p.probeNetwork(candidate)
	conn, err := p.dialer.DialContext(ctx, network, candidate.Address)
	latency := time.Since(started)
	if err != nil {
		result.Reason = fmt.Sprintf("dial_failed: %v", err)
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
		warpEnabled, err := p.checker.CheckWarp(ctx, candidate)
		if err != nil {
			result.Available = false
			result.WarpEnabled = false
			result.Reason = fmt.Sprintf("warp_check_failed: %v", err)
			return result
		}
		result.Available = warpEnabled
		result.WarpEnabled = warpEnabled
		if !warpEnabled {
			result.Reason = "warp_check_failed: unavailable"
		}
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

// ApplyProbeResults 将探测结果合并回候选列表。
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

// ProbeCandidates 用注入探测器更新候选状态。
func ProbeCandidates(prober Prober, candidates []Candidate) []Candidate {
	if prober == nil {
		return append([]Candidate(nil), candidates...)
	}
	return ApplyProbeResults(candidates, prober.Probe(candidates))
}

// BatchProbe 将探测、排序和最佳选择串联起来。
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

// BatchProbePlan 先展开计划再执行批量探测。
func BatchProbePlan(plan Plan, prober Prober, port, limit int) BatchResult {
	if port <= 0 {
		port = DefaultProbePort
	}
	if limit <= 0 {
		limit = DefaultProbeSampleLimit
	}
	return BatchProbe(prober, BuildCandidatesFromPlan(plan, port, limit))
}
