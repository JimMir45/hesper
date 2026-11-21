package detection

import (
	"context"
	"errors"

	"github.com/JimMir45/hesper/internal/findings"
)

// AutoJudge implements judge.mode=auto (design §5.5): online when the
// Velociraptor endpoint is healthy, offline otherwise.
type AutoJudge struct {
	Online  *VelociraptorJudge
	Offline *OfflineJudge
	// Health overrides the online health check in tests.
	Health func(ctx context.Context) bool

	lastPath string // "velociraptor" | "offline" — observable for reports
}

// LastPath reports which path served the most recent Correlate call.
func (a *AutoJudge) LastPath() string { return a.lastPath }

func (a *AutoJudge) online(ctx context.Context) bool {
	if a.Health != nil {
		return a.Health(ctx)
	}
	if a.Online == nil || a.Online.Client == nil {
		return false
	}
	return a.Online.Client.Health(ctx)
}

// Correlate delegates to the healthy path; both failing is an error, never
// a silent empty result (design §6 JudgeError semantics live at the caller).
func (a *AutoJudge) Correlate(ctx context.Context, w Window, refs []ActionRef) ([]findings.Hit, error) {
	if a.online(ctx) {
		a.lastPath = "velociraptor"
		return a.Online.Correlate(ctx, w, refs)
	}
	if a.Offline == nil {
		return nil, errors.New("auto judge: offline path not configured")
	}
	a.lastPath = "offline"
	return a.Offline.Correlate(ctx, w, refs)
}
