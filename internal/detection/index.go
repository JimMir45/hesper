package detection

import (
	"encoding/json"
	"fmt"
	"os"
)

// RuleMeta is the attribution record for one Sigma rule. Author is REQUIRED
// for SigmaHQ-derived rules (DRL-1.1); a missing author makes the judge
// fail, not the hit silently pass through unattributed.
type RuleMeta struct {
	Author string `json:"author"`
	Level  string `json:"level,omitempty"`
}

// RuleIndex maps rule identifiers (the rule title/name reported by both
// chainsaw and Velociraptor curated Sigma) to their metadata.
type RuleIndex map[string]RuleMeta

// LoadRuleIndex reads a JSON rule index produced by
// scripts/build-sigma-index.py from a SigmaHQ checkout.
func LoadRuleIndex(path string) (RuleIndex, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("rule index: read %s: %w", path, err)
	}
	var idx RuleIndex
	if err := json.Unmarshal(b, &idx); err != nil {
		return nil, fmt.Errorf("rule index: parse %s: %w", path, err)
	}
	for name, meta := range idx {
		if meta.Author == "" {
			return nil, fmt.Errorf("rule index: %s: author is mandatory (DRL-1.1)", name)
		}
	}
	return idx, nil
}
