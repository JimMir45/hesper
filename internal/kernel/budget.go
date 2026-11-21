package kernel

import (
	"sync"
	"time"
)

// Budgeter enforces the hard action/time limits of a scope (design §5.1).
// Exhaustion is not an error: the run drains and terminates gracefully
// toward DONE (design §6, BudgetExhausted).
type Budgeter struct {
	mu         sync.Mutex
	maxActions int
	used       int
	deadline   time.Time
	clock      func() time.Time
}

// NewBudgeter builds a Budgeter with the real clock.
func NewBudgeter(b Budget) *Budgeter {
	return newBudgeter(b, time.Now)
}

func newBudgeter(b Budget, clock func() time.Time) *Budgeter {
	start := clock()
	return &Budgeter{
		maxActions: b.MaxActions,
		deadline:   start.Add(time.Duration(b.MaxMinutes) * time.Minute),
		used:       0,
		clock:      clock,
	}
}

// SpendAction atomically consumes one action slot. It refuses when the
// action budget is spent or the wall-clock deadline has passed.
func (b *Budgeter) SpendAction() (ok bool, reason string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if !b.clock().Before(b.deadline) {
		return false, "time budget exhausted"
	}
	if b.used >= b.maxActions {
		return false, "action budget exhausted"
	}
	b.used++
	return true, ""
}

// Exhausted reports whether any budget dimension is spent, with the reason.
func (b *Budgeter) Exhausted() (bool, string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if !b.clock().Before(b.deadline) {
		return true, "time budget exhausted"
	}
	if b.used >= b.maxActions {
		return true, "action budget exhausted"
	}
	return false, ""
}

// Dump returns the budgeter's accounting (used actions, deadline) for
// run-state persistence (design §3 resume path).
func (b *Budgeter) Dump() (used int, deadline time.Time) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.used, b.deadline
}

// RestoreBudgeter rebuilds a budgeter with prior accounting, so a resumed
// run continues under the ORIGINAL limits — a resume never mints budget.
func RestoreBudgeter(b Budget, used int, deadline time.Time, clock func() time.Time) *Budgeter {
	return &Budgeter{
		maxActions: b.MaxActions,
		deadline:   deadline,
		used:       used,
		clock:      clock,
	}
}
