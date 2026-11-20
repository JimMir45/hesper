package kernel

import (
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"time"
)

// AuditLog is the append-only JSONL event trail of a run (design §4.3, §5.1).
// Single writer in production (the run loop); methods are mutex-guarded for
// defensive safety. The audit file is part of the evidence package and must
// never be edited after the run.
type AuditLog struct {
	mu  sync.Mutex
	f   *os.File
	seq int
}

type auditLine struct {
	Seq   int            `json:"seq"`
	TS    string         `json:"ts"`
	Event string         `json:"event"`
	Data  map[string]any `json:"data,omitempty"`
}

// OpenAudit opens (creating if needed) the audit file for appending.
func OpenAudit(path string) (*AuditLog, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return nil, fmt.Errorf("audit: open %s: %w", path, err)
	}
	return &AuditLog{f: f}, nil
}

// Append writes one event line {seq, ts, event, data}. Seq is monotonic
// within this process instance. Marshal failure rolls the seq back so a
// retried event does not leave a gap.
func (a *AuditLog) Append(event string, data map[string]any) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.seq++
	line := auditLine{
		Seq:   a.seq,
		TS:    time.Now().UTC().Format(time.RFC3339Nano),
		Event: event,
		Data:  data,
	}
	b, err := json.Marshal(line)
	if err != nil {
		a.seq--
		return fmt.Errorf("audit: marshal %q: %w", event, err)
	}
	if _, err := a.f.WriteString(string(b) + "\n"); err != nil {
		a.seq--
		return fmt.Errorf("audit: write: %w", err)
	}
	return nil
}

// Close syncs and closes the underlying file.
func (a *AuditLog) Close() error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.f == nil {
		return nil
	}
	if err := a.f.Sync(); err != nil {
		_ = a.f.Close()
		a.f = nil
		return fmt.Errorf("audit: sync: %w", err)
	}
	err := a.f.Close()
	a.f = nil
	return err
}
