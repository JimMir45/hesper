package kernel

import (
	"strings"
	"testing"
	"time"
)

type fakeClock struct{ t time.Time }

func (f *fakeClock) Now() time.Time      { return f.t }
func (f *fakeClock) Advance(d time.Duration) { f.t = f.t.Add(d) }

func TestBudgeterSpendsWithinBudget(t *testing.T) {
	clock := &fakeClock{t: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}
	b := newBudgeter(Budget{MaxActions: 2, MaxMinutes: 30}, clock.Now)

	for i := 0; i < 2; i++ {
		ok, reason := b.SpendAction()
		if !ok {
			t.Fatalf("spend %d: unexpected deny: %s", i+1, reason)
		}
	}
	if ok, reason := b.SpendAction(); ok {
		t.Fatalf("third spend must be denied, got ok (reason=%q)", reason)
	} else if !strings.Contains(reason, "action budget exhausted") {
		t.Fatalf("wrong deny reason: %q", reason)
	}
}

func TestBudgeterTimeDeadline(t *testing.T) {
	clock := &fakeClock{t: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}
	b := newBudgeter(Budget{MaxActions: 10, MaxMinutes: 30}, clock.Now)

	clock.Advance(29 * time.Minute)
	if ok, _ := b.SpendAction(); !ok {
		t.Fatal("spend before deadline must succeed")
	}
	clock.Advance(2 * time.Minute) // past the 30-minute deadline
	if ok, reason := b.SpendAction(); ok {
		t.Fatal("spend past deadline must be denied")
	} else if !strings.Contains(reason, "time budget exhausted") {
		t.Fatalf("wrong deny reason: %q", reason)
	}
	if exhausted, reason := b.Exhausted(); !exhausted || !strings.Contains(reason, "time") {
		t.Fatalf("Exhausted must report time budget: %v %q", exhausted, reason)
	}
}

func TestBudgeterExhaustedReflectsActions(t *testing.T) {
	clock := &fakeClock{t: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}
	b := newBudgeter(Budget{MaxActions: 1, MaxMinutes: 30}, clock.Now)

	if exhausted, _ := b.Exhausted(); exhausted {
		t.Fatal("fresh budgeter must not be exhausted")
	}
	_, _ = b.SpendAction()
	if exhausted, reason := b.Exhausted(); !exhausted || !strings.Contains(reason, "action") {
		t.Fatalf("Exhausted must report action budget: %v %q", exhausted, reason)
	}
}
