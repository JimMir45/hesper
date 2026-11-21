package kernel

import "testing"

func TestEgressMonitorThreshold(t *testing.T) {
	m := NewEgressMonitor(0) // 0 ⇒ design default 3
	for i := 1; i <= 2; i++ {
		strikes, stop := m.Record()
		if strikes != i || stop {
			t.Fatalf("strike %d: strikes=%d stop=%v (threshold must not trip before 3)", i, strikes, stop)
		}
	}
	strikes, stop := m.Record()
	if strikes != 3 || !stop {
		t.Fatalf("third strike: strikes=%d stop=%v, want 3/true", strikes, stop)
	}
	if m.Count() != 3 {
		t.Fatalf("count=%d", m.Count())
	}
}

func TestEgressMonitorCustomThreshold(t *testing.T) {
	m := NewEgressMonitor(1)
	if _, stop := m.Record(); !stop {
		t.Fatal("threshold 1 must stop at first violation")
	}
}
