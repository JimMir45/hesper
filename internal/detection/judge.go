// Package detection implements the Detection Judge (design §5.5): it
// correlates executed actions with Sigma-rule hits inside a time window,
// joined on ATT&CK technique IDs. Two implementations — VelociraptorJudge
// (online) and OfflineJudge (chainsaw over EVTX) — sit behind one Judge
// interface; judge.mode=auto picks online when the endpoint is healthy.
//
// Attribution contract (DRL-1.1): SigmaHQ-derived rules carry their author
// into findings.Hit.Author. A hit whose rule cannot be attributed is an
// error — attribution is fail-closed, never silently dropped.
package detection

import (
	"context"
	"time"

	"github.com/JimMir45/hesper/internal/findings"
)

// Window is the correlation window: [From, To].
type Window struct {
	From time.Time
	To   time.Time
}

// ActionRef is one executed action the judge correlates against.
type ActionRef struct {
	ID       string    // action id in the run
	AttackID string    // ATT&CK technique id, e.g. "T1003.003" (join key)
	TS       time.Time // action execution time
}

// Judge correlates actions against detection hits (design §5.5).
type Judge interface {
	Correlate(ctx context.Context, w Window, refs []ActionRef) ([]findings.Hit, error)
}

// ByRule groups hits per rule id, the shape the findings module consumes
// (findings.Outcome.HitsByRule).
func ByRule(hits []findings.Hit) map[string][]findings.Hit {
	if len(hits) == 0 {
		return nil
	}
	m := make(map[string][]findings.Hit, len(hits))
	for _, h := range hits {
		m[h.RuleID] = append(m[h.RuleID], h)
	}
	return m
}
