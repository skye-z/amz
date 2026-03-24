package discovery

// Cache 描述可供下次复用的候选缓存。
type Cache struct {
	Selected   Candidate
	Candidates []Candidate
}

// Remember 将本次发现结果写回缓存。
func Remember(current Cache, batch BatchResult) Cache {
	next := Cache{
		Selected: current.Selected,
	}
	if len(batch.Ranked) > 0 {
		next.Candidates = dedupeCandidates(batch.Ranked)
	} else {
		next.Candidates = dedupeCandidates(current.Candidates)
	}
	if batch.OK {
		next.Selected = batch.Best
	}
	if next.Selected.Address != "" {
		next.Candidates = dedupeCandidates(append([]Candidate{next.Selected}, next.Candidates...))
	}
	return next
}

func buildCacheCandidates(cache Cache) []Candidate {
	preferred := make([]Candidate, 0, len(cache.Candidates)+1)
	if cache.Selected.Address != "" {
		preferred = append(preferred, cache.Selected)
	}
	preferred = append(preferred, cache.Candidates...)
	return dedupeCandidates(preferred)
}
