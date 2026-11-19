package inputguard

// TopicFilterConfig configures TopicFilter.
type TopicFilterConfig struct {
	// Topics: only these topics are filtered.
	Topics []string
	// DryRun: report (OnFinding) without changing the payload, for a rollout in observe-only mode.
	DryRun bool
	// OnFinding is called when a payload has findings. The report never contains values.
	OnFinding func(topic string, r Report)
}

// TopicFilter returns a filter for message payloads (Kafka, NATS, queues): a second line of defence behind the
// HTTP middleware, for paths that produce messages without going through it (replays, jobs, new publishers). It
// never blocks: a payload that is rejected or not JSON is passed through unchanged.
func (g *Guard) TopicFilter(cfg TopicFilterConfig) func(topic string, payload []byte) []byte {
	set := make(map[string]bool, len(cfg.Topics))
	for _, t := range cfg.Topics {
		if t != "" {
			set[t] = true
		}
	}
	return func(topic string, payload []byte) []byte {
		if !set[topic] {
			return payload
		}
		out, r := g.ProcessJSON(payload)
		if len(r.Findings) == 0 && !r.LimitExceeded {
			return payload
		}
		if cfg.OnFinding != nil {
			cfg.OnFinding(topic, r)
		}
		if cfg.DryRun || r.Rejected {
			return payload
		}
		return out
	}
}
