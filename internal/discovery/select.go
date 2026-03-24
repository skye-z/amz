package discovery

import (
	"net"
	"sort"
	"strconv"
	"strings"
)

// Scan 描述自动发现输入。
type Scan struct {
	Source  string
	Range4  []string
	Range6  []string
	Fixed   []string
	Domains []string
}

// Registration 描述已注册设备返回的候选信息。
type Registration struct {
	EndpointV4    string
	EndpointV6    string
	EndpointHost  string
	EndpointPorts []uint16
}

// Input 描述一次发现所需的最小输入。
type Input struct {
	ExplicitEndpoint string
	Official         []string
	Registration     Registration
	Scan             Scan
	Cache            Cache
}

// RankCandidates 按可用性、WARP 状态、端口优先级、来源和时延排序。
func RankCandidates(candidates []Candidate) []Candidate {
	ranked := append([]Candidate(nil), candidates...)
	sort.SliceStable(ranked, func(i, j int) bool {
		left := ranked[i]
		right := ranked[j]
		if left.Available != right.Available {
			return left.Available
		}
		if left.WarpEnabled != right.WarpEnabled {
			return left.WarpEnabled
		}
		leftPortRank := warpProxyPortRank(left.Address)
		rightPortRank := warpProxyPortRank(right.Address)
		if leftPortRank != rightPortRank {
			return leftPortRank < rightPortRank
		}
		leftSourceRank := candidateSourceRank(left.Source)
		rightSourceRank := candidateSourceRank(right.Source)
		if leftSourceRank != rightSourceRank {
			return leftSourceRank < rightSourceRank
		}
		return left.Latency < right.Latency
	})
	return ranked
}

// PickBestCandidate 选择排序后的首个可用候选。
func PickBestCandidate(candidates []Candidate) (Candidate, bool) {
	ranked := RankCandidates(candidates)
	for _, candidate := range ranked {
		if candidate.Available {
			return candidate, true
		}
	}
	return Candidate{}, false
}

// BuildVerificationCandidates 构建 SDK 内部使用的优先/回退候选列表。
func BuildVerificationCandidates(input Input, port, limit int) ([]Candidate, []Candidate) {
	if explicit := strings.TrimSpace(input.ExplicitEndpoint); explicit != "" {
		source, err := ParseSource(explicit)
		if err == nil {
			return BuildCandidates(source), nil
		}
		return []Candidate{{
			Address:     explicit,
			Source:      SourceDomain,
			Available:   true,
			WarpEnabled: true,
		}}, nil
	}

	preferred := buildCacheCandidates(input.Cache)
	preferred = append(preferred, buildFixedCandidates(input.Official)...)

	preferredPlan := buildPreferredPlan(input.Registration)
	preferred = append(preferred, buildProbeCandidatesFromPlan(preferredPlan, port, limit)...)
	preferred = dedupeCandidates(preferred)

	fallbackPlan := Plan{
		Source:  Source{Kind: SourceAuto, Value: strings.TrimSpace(input.Scan.Source)},
		Range4:  append([]string(nil), input.Scan.Range4...),
		Range6:  append([]string(nil), input.Scan.Range6...),
		Fixed:   append([]string(nil), input.Scan.Fixed...),
		Domains: append([]string(nil), input.Scan.Domains...),
	}
	fallback := buildProbeCandidatesFromPlan(fallbackPlan, port, limit)
	return preferred, fallback
}

// Select 构建候选并执行探测排序。
func Select(input Input, prober Prober, port, limit int) BatchResult {
	preferred, fallback := BuildVerificationCandidates(input, port, limit)
	combined := append([]Candidate(nil), preferred...)
	for _, candidate := range fallback {
		if containsCandidate(combined, candidate.Address) {
			continue
		}
		combined = append(combined, candidate)
	}
	return probeCandidateSet(prober, combined)
}

func probeCandidateSet(prober Prober, candidates []Candidate) BatchResult {
	if len(candidates) == 0 {
		return BatchResult{}
	}
	prepared := make([]Candidate, 0, len(candidates))
	for _, candidate := range candidates {
		candidate.Available = false
		candidate.WarpEnabled = false
		candidate.Latency = 0
		candidate.Reason = "not_probed"
		prepared = append(prepared, candidate)
	}
	batch := BatchProbe(prober, prepared)
	if batch.OK || !allCandidatesNotProbed(batch.Ranked) {
		return batch
	}
	return BatchProbe(prober, candidates)
}

func allCandidatesNotProbed(candidates []Candidate) bool {
	if len(candidates) == 0 {
		return false
	}
	for _, candidate := range candidates {
		if strings.TrimSpace(candidate.Reason) != "not_probed" {
			return false
		}
	}
	return true
}

func buildPreferredPlan(state Registration) Plan {
	plan := Plan{}
	if len(state.EndpointPorts) > 0 {
		if strings.TrimSpace(state.EndpointHost) != "" {
			host := strings.TrimSpace(state.EndpointHost)
			if parsed, _, err := net.SplitHostPort(host); err == nil {
				host = parsed
			}
			for _, port := range state.EndpointPorts {
				plan.Domains = append(plan.Domains, net.JoinHostPort(host, strconv.Itoa(int(port))))
			}
		}
		if strings.TrimSpace(state.EndpointV4) != "" {
			host, _, err := net.SplitHostPort(strings.TrimSpace(state.EndpointV4))
			if err == nil {
				for _, port := range state.EndpointPorts {
					plan.Fixed = append(plan.Fixed, net.JoinHostPort(host, strconv.Itoa(int(port))))
				}
				for _, fallbackHost := range observedWarpProxyFallbackHosts(host) {
					for _, port := range state.EndpointPorts {
						plan.Fixed = append(plan.Fixed, net.JoinHostPort(fallbackHost, strconv.Itoa(int(port))))
					}
				}
			} else {
				plan.Fixed = append(plan.Fixed, strings.TrimSpace(state.EndpointV4))
			}
		}
		if strings.TrimSpace(state.EndpointV6) != "" {
			host, _, err := net.SplitHostPort(strings.TrimSpace(state.EndpointV6))
			if err == nil {
				for _, port := range state.EndpointPorts {
					plan.Fixed = append(plan.Fixed, net.JoinHostPort(host, strconv.Itoa(int(port))))
				}
			} else {
				plan.Fixed = append(plan.Fixed, strings.TrimSpace(state.EndpointV6))
			}
		}
		return plan
	}

	if strings.TrimSpace(state.EndpointHost) != "" {
		plan.Domains = append(plan.Domains, strings.TrimSpace(state.EndpointHost))
	}
	if strings.TrimSpace(state.EndpointV4) != "" {
		plan.Fixed = append(plan.Fixed, strings.TrimSpace(state.EndpointV4))
	}
	if strings.TrimSpace(state.EndpointV6) != "" {
		plan.Fixed = append(plan.Fixed, strings.TrimSpace(state.EndpointV6))
	}
	return plan
}

func observedWarpProxyFallbackHosts(host string) []string {
	ip := net.ParseIP(strings.TrimSpace(host))
	ip4 := ip.To4()
	if ip4 == nil {
		return nil
	}
	if ip4[0] == 162 && ip4[1] == 159 && ip4[2] == 198 && ip4[3] == 1 {
		return []string{"162.159.198.2"}
	}
	return nil
}

func buildProbeCandidatesFromPlan(plan Plan, port, limit int) []Candidate {
	candidates := make([]Candidate, 0)
	appendUnique := func(items []Candidate) {
		for _, candidate := range items {
			if containsCandidate(candidates, candidate.Address) {
				continue
			}
			candidates = append(candidates, candidate)
		}
	}
	appendUnique(BuildCandidatesFromPlan(Plan{Fixed: plan.Fixed, Domains: plan.Domains}, port, limit))
	appendUnique(BuildCandidatesFromPlan(Plan{Range4: plan.Range4}, port, limit))
	appendUnique(BuildCandidatesFromPlan(Plan{Range6: plan.Range6}, port, limit))
	return candidates
}

func buildFixedCandidates(addresses []string) []Candidate {
	out := make([]Candidate, 0, len(addresses))
	for _, address := range addresses {
		trimmed := strings.TrimSpace(address)
		if trimmed == "" {
			continue
		}
		out = append(out, Candidate{
			Address:     trimmed,
			Source:      SourceFixed,
			Available:   true,
			WarpEnabled: true,
		})
	}
	return out
}

func dedupeCandidates(input []Candidate) []Candidate {
	seen := map[string]bool{}
	out := make([]Candidate, 0, len(input))
	for _, candidate := range input {
		address := strings.TrimSpace(candidate.Address)
		if address == "" || seen[address] {
			continue
		}
		seen[address] = true
		candidate.Address = address
		out = append(out, candidate)
	}
	return out
}

func containsCandidate(candidates []Candidate, address string) bool {
	address = strings.TrimSpace(address)
	for _, candidate := range candidates {
		if candidate.Address == address {
			return true
		}
	}
	return false
}

func warpProxyPortRank(address string) int {
	_, port, err := net.SplitHostPort(strings.TrimSpace(address))
	if err != nil {
		return 100
	}
	switch port {
	case "443":
		return 0
	case "500":
		return 1
	case "1701":
		return 2
	case "4500":
		return 3
	case "4443":
		return 4
	case "8443":
		return 5
	case "8095":
		return 6
	default:
		return 100
	}
}

func candidateSourceRank(source string) int {
	switch strings.TrimSpace(source) {
	case SourceFixed:
		return 0
	case SourceDomain:
		return 1
	case SourceAuto:
		return 2
	default:
		return 100
	}
}
