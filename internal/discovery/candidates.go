package discovery

import (
	"fmt"
	"net"
	"net/netip"
	"strings"
	"time"
)

const (
	// SourceFixed 表示直接使用固定 IP 或主机端点。
	SourceFixed = "fixed"
	// SourceDomain 表示使用域名端点。
	SourceDomain = "domain"
	// SourceAuto 表示通过自动发现流程生成候选。
	SourceAuto = "auto"
)

// Source 描述端点来源类型和值。
type Source struct {
	Kind  string
	Value string
}

// Candidate 描述单个候选端点及其探测状态。
type Candidate struct {
	Address     string
	Source      string
	Latency     time.Duration
	Available   bool
	WarpEnabled bool
	Reason      string
}

// ProbeResult 描述候选的探测结果。
type ProbeResult struct {
	Address     string
	Latency     time.Duration
	Available   bool
	WarpEnabled bool
	Reason      string
}

// BatchResult 描述一批候选探测后的聚合结果。
type BatchResult struct {
	Candidates []Candidate
	Ranked     []Candidate
	Best       Candidate
	OK         bool
}

// Prober 抽象候选探测能力。
type Prober interface {
	Probe([]Candidate) []ProbeResult
}

// Plan 描述候选展开计划。
type Plan struct {
	Source  Source
	Range4  []string
	Range6  []string
	Fixed   []string
	Domains []string
}

// ParseSource 将字符串端点解析为来源模型。
func ParseSource(input string) (Source, error) {
	trimmed := strings.TrimSpace(input)
	if trimmed == "" {
		return Source{}, fmt.Errorf("endpoint source is required")
	}
	if trimmed == SourceAuto {
		return Source{Kind: SourceAuto, Value: trimmed}, nil
	}
	host, _, err := net.SplitHostPort(trimmed)
	if err != nil {
		return Source{}, fmt.Errorf("invalid endpoint source: %w", err)
	}
	if net.ParseIP(host) != nil {
		return Source{Kind: SourceFixed, Value: trimmed}, nil
	}
	return Source{Kind: SourceDomain, Value: trimmed}, nil
}

// BuildCandidates 根据来源生成基础候选。
func BuildCandidates(source Source) []Candidate {
	switch source.Kind {
	case SourceFixed, SourceDomain:
		return []Candidate{{
			Address:     strings.TrimSpace(source.Value),
			Source:      source.Kind,
			Available:   true,
			WarpEnabled: true,
		}}
	case SourceAuto:
		return []Candidate{
			{Address: "162.159.198.1:443", Source: SourceAuto, Available: true, WarpEnabled: true, Latency: 30 * time.Millisecond},
			{Address: "162.159.198.2:443", Source: SourceAuto, Available: true, WarpEnabled: true, Latency: 45 * time.Millisecond},
		}
	default:
		return nil
	}
}

// ExpandCIDRSamples 从 CIDR 中按顺序提取少量样本地址。
func ExpandCIDRSamples(cidrs []string, port, limit int) []string {
	if limit <= 0 {
		return nil
	}
	results := make([]string, 0, limit)
	for _, raw := range cidrs {
		prefix, addr, ok := cidrSampleStart(raw)
		if !ok {
			continue
		}
		var done bool
		results, done = appendCIDRSamples(results, prefix, addr, port, limit)
		if done {
			return results
		}
	}
	return results
}

func cidrSampleStart(raw string) (netip.Prefix, netip.Addr, bool) {
	prefix, err := netip.ParsePrefix(strings.TrimSpace(raw))
	if err != nil {
		return netip.Prefix{}, netip.Addr{}, false
	}
	addr := prefix.Addr()
	if prefix.Bits() < addr.BitLen() {
		next := addr.Next()
		if next.IsValid() {
			addr = next
		}
	}
	return prefix, addr, true
}

func appendCIDRSamples(results []string, prefix netip.Prefix, addr netip.Addr, port, limit int) ([]string, bool) {
	for i := 0; i < limit && prefix.Contains(addr); i++ {
		results = append(results, net.JoinHostPort(addr.String(), fmt.Sprintf("%d", port)))
		if len(results) >= limit {
			return results, true
		}
		next := addr.Next()
		if !next.IsValid() {
			return results, false
		}
		addr = next
	}
	return results, false
}

// BuildCandidatesFromPlan 将发现计划展开为候选列表。
func BuildCandidatesFromPlan(plan Plan, port, limit int) []Candidate {
	candidates := make([]Candidate, 0)
	seen := make(map[string]struct{})
	appendCandidate := func(candidate Candidate) {
		address := strings.TrimSpace(candidate.Address)
		if address == "" {
			return
		}
		if _, ok := seen[address]; ok {
			return
		}
		seen[address] = struct{}{}
		candidate.Address = address
		candidates = append(candidates, candidate)
	}
	for _, address := range plan.Fixed {
		appendCandidate(Candidate{Address: address, Source: SourceFixed, Available: true, WarpEnabled: true})
	}
	for _, address := range plan.Domains {
		appendCandidate(Candidate{Address: address, Source: SourceDomain, Available: true, WarpEnabled: true})
	}
	for _, address := range ExpandCIDRSamples(plan.Range4, port, limit) {
		appendCandidate(Candidate{Address: address, Source: SourceAuto, Available: true, WarpEnabled: true})
	}
	for _, address := range ExpandCIDRSamples(plan.Range6, port, limit) {
		appendCandidate(Candidate{Address: address, Source: SourceAuto, Available: true, WarpEnabled: true})
	}
	if len(candidates) == 0 {
		candidates = append(candidates, BuildCandidates(plan.Source)...)
	}
	return candidates
}
