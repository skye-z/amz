package amz

import (
	"context"
	"strings"
	"time"

	"github.com/skye-z/amz/internal/discovery"
)

type loggingProber struct {
	logger Logger
	base   discovery.Prober
}

func newLoggingProber(logger Logger, base discovery.Prober) discovery.Prober {
	if logger == nil || base == nil {
		return base
	}
	return &loggingProber{
		logger: withAction(logger, "SELECT"),
		base:   base,
	}
}

func (p *loggingProber) Probe(candidates []discovery.Candidate) []discovery.ProbeResult {
	if p == nil || p.base == nil {
		return nil
	}

	results := make([]discovery.ProbeResult, 0, len(candidates))
	for idx, candidate := range candidates {
		logEvent(p.logger, "managed_runtime", "endpoint.probe.begin",
			field("candidate", candidate.Address),
			field("source", candidate.Source),
			field("index", idx+1),
			field("total", len(candidates)),
		)

		started := time.Now()
		probed := p.base.Probe([]discovery.Candidate{candidate})
		if len(probed) == 0 {
			logEvent(p.logger, "managed_runtime", "endpoint.probe.failed",
				field("candidate", candidate.Address),
				field("source", candidate.Source),
				field("reason", "no_probe_result"),
				durationField("duration", time.Since(started)),
			)
			continue
		}

		result := probed[0]
		results = append(results, result)
		event := "endpoint.probe.success"
		if !result.Available {
			event = "endpoint.probe.failed"
		}
		logEvent(p.logger, "managed_runtime", event,
			field("candidate", candidate.Address),
			field("source", candidate.Source),
			field("available", result.Available),
			field("warp_enabled", result.WarpEnabled),
			field("probe_latency", result.Latency),
			field("reason", strings.TrimSpace(result.Reason)),
			durationField("duration", time.Since(started)),
		)
	}
	return results
}

type loggingProbeObserver struct {
	logger Logger
}

func newLoggingProbeObserver(logger Logger) discovery.ProbeObserver {
	if logger == nil {
		return nil
	}
	return &loggingProbeObserver{logger: withAction(logger, "SELECT")}
}

func (o *loggingProbeObserver) OnProbeStart(candidate discovery.Candidate, index, total int) {
	logEvent(o.logger, "managed_runtime", "endpoint.probe.begin",
		field("candidate", candidate.Address),
		field("source", candidate.Source),
		field("index", index),
		field("total", total),
	)
}

func (o *loggingProbeObserver) OnProbeDone(candidate discovery.Candidate, result discovery.ProbeResult, duration time.Duration, index, total int) {
	event := "endpoint.probe.success"
	if !result.Available {
		event = "endpoint.probe.failed"
	}
	logEvent(o.logger, "managed_runtime", event,
		field("candidate", candidate.Address),
		field("source", candidate.Source),
		field("available", result.Available),
		field("warp_enabled", result.WarpEnabled),
		field("probe_latency", result.Latency),
		field("reason", strings.TrimSpace(result.Reason)),
		field("index", index),
		field("total", total),
		durationField("duration", duration),
	)
}

func (o *loggingProbeObserver) OnWarpCheckStart(candidate discovery.Candidate) {
	logEvent(o.logger, "managed_runtime", "endpoint.warp_check.begin",
		field("candidate", candidate.Address),
		field("source", candidate.Source),
	)
}

func (o *loggingProbeObserver) OnWarpCheckDone(candidate discovery.Candidate, ok bool, err error, duration time.Duration) {
	event := "endpoint.warp_check.success"
	if err != nil || !ok {
		event = "endpoint.warp_check.failed"
	}
	fields := []logField{
		field("candidate", candidate.Address),
		field("source", candidate.Source),
		durationField("duration", duration),
	}
	if err != nil {
		fields = append(fields, field("error", err))
	} else if !ok {
		fields = append(fields, field("reason", "unavailable"))
	}
	logEvent(o.logger, "managed_runtime", event, fields...)
}

type loggingWarpStatusChecker struct {
	logger Logger
	base   discovery.WarpStatusChecker
}

func newLoggingWarpStatusChecker(logger Logger, base discovery.WarpStatusChecker) discovery.WarpStatusChecker {
	if logger == nil || base == nil {
		return base
	}
	return &loggingWarpStatusChecker{
		logger: withAction(logger, "SELECT"),
		base:   base,
	}
}

func (c *loggingWarpStatusChecker) CheckWarp(ctx context.Context, candidate discovery.Candidate) (bool, error) {
	if c == nil || c.base == nil {
		return false, nil
	}

	started := time.Now()
	logEvent(c.logger, "managed_runtime", "endpoint.warp_check.begin",
		field("candidate", candidate.Address),
		field("source", candidate.Source),
	)
	ok, err := c.base.CheckWarp(ctx, candidate)
	if err != nil {
		logEvent(c.logger, "managed_runtime", "endpoint.warp_check.failed",
			field("candidate", candidate.Address),
			field("source", candidate.Source),
			field("error", err),
			durationField("duration", time.Since(started)),
		)
		return false, err
	}
	if !ok {
		logEvent(c.logger, "managed_runtime", "endpoint.warp_check.failed",
			field("candidate", candidate.Address),
			field("source", candidate.Source),
			field("reason", "unavailable"),
			durationField("duration", time.Since(started)),
		)
		return false, nil
	}
	logEvent(c.logger, "managed_runtime", "endpoint.warp_check.success",
		field("candidate", candidate.Address),
		field("source", candidate.Source),
		durationField("duration", time.Since(started)),
	)
	return true, nil
}

func mergeUniqueCandidates(preferred, fallback []discovery.Candidate) []discovery.Candidate {
	combined := append([]discovery.Candidate(nil), preferred...)
	seen := make(map[string]bool, len(preferred))
	for _, candidate := range preferred {
		seen[strings.TrimSpace(candidate.Address)] = true
	}
	for _, candidate := range fallback {
		address := strings.TrimSpace(candidate.Address)
		if address == "" || seen[address] {
			continue
		}
		seen[address] = true
		combined = append(combined, candidate)
	}
	return combined
}
