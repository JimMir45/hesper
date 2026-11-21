package kernel

import "sync"

// egressViolationThreshold: design §6 — AdapterEgressViolation count ≥3 ⇒
// the run is STOPPED (policy stop, exit 1, distinct from the kill switch's
// 130).
const egressViolationThreshold = 3

// EgressMonitor counts egress violations for one run and answers whether the
// policy stop threshold has been reached. Safe for concurrent use.
type EgressMonitor struct {
	mu        sync.Mutex
	count     int
	threshold int
}

// NewEgressMonitor builds a monitor; threshold <= 0 falls back to the design
// default (3).
func NewEgressMonitor(threshold int) *EgressMonitor {
	if threshold <= 0 {
		threshold = egressViolationThreshold
	}
	return &EgressMonitor{threshold: threshold}
}

// Record adds one violation and reports the strike count and whether the run
// must stop.
func (m *EgressMonitor) Record() (strikes int, stop bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.count++
	return m.count, m.count >= m.threshold
}

// Count reports violations recorded so far.
func (m *EgressMonitor) Count() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.count
}
