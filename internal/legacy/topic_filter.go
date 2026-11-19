package legacy

// TopicFilterConfig: cấu hình chốt lọc Kafka.
type TopicFilterConfig struct {
	// Topics: chỉ các topic này bị lọc (topic rỗng bị bỏ qua).
	Topics []string
	// DryRun: chỉ báo (OnCleaned) mà không đổi bytes — chế độ rollout `log`.
	DryRun bool
	// OnCleaned được gọi khi payload có nội dung độc (Report không bao giờ chứa giá trị). nil = không báo.
	OnCleaned func(topic string, rep Report)
}

// TopicFilter: chốt lọc thứ hai — làm sạch payload JSON trước khi publish vào các topic event. Che các đường tạo
// event KHÔNG qua middleware HTTP (test-run, replay dead-letter, publisher thêm sau này). Luôn chế độ Clean và
// không bao giờ chặn publish: lỗi / payload không phải JSON ⇒ trả nguyên.
func TopicFilter(cfg TopicFilterConfig) func(topic string, value []byte) []byte {
	set := make(map[string]bool, len(cfg.Topics))
	for _, t := range cfg.Topics {
		if t != "" {
			set[t] = true
		}
	}
	return func(topic string, value []byte) []byte {
		if !set[topic] {
			return value
		}
		out, rep, err := CleanJSON(value, ModeClean, nil)
		if err != nil || !rep.Changed {
			return value
		}
		if cfg.OnCleaned != nil {
			cfg.OnCleaned(topic, rep)
		}
		if cfg.DryRun {
			return value
		}
		return out
	}
}

// SummarizeFindings: danh sách luật và field (không trùng, tối đa 5 field) — không bao giờ kèm giá trị.
func SummarizeFindings(fs []PathFinding) (string, string) {
	const maxFields = 5
	seenRule, seenField := map[RuleID]bool{}, map[string]bool{}
	rules, fields := "", ""
	nFields := 0
	for _, f := range fs {
		if !seenRule[f.Rule] {
			seenRule[f.Rule] = true
			if rules != "" {
				rules += ","
			}
			rules += string(f.Rule)
		}
		if !seenField[f.Path] && nFields < maxFields {
			seenField[f.Path] = true
			if fields != "" {
				fields += ","
			}
			fields += f.Path
			nFields++
		}
	}
	return rules, fields
}
