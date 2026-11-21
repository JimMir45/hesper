// Package evidence implements the Evidence Store (design §4.3, §5.4): an
// append-only, hash-chained record trail whose integrity — chain linkage
// and artifact bytes — is machine-verifiable (`hesper evidence verify`).
package evidence

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
)

// Artifact is one captured piece of proof. Path is relative to the run
// directory so a run directory is a portable evidence package.
type Artifact struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
	Kind   string `json:"kind"` // stdout | stderr | body | file | evtx | ...
}

// Result is the execution verdict carried by an action.executed record.
type Result struct {
	Success     bool   `json:"success"`
	Detail      string `json:"detail,omitempty"`
	NotHappened bool   `json:"not_happened,omitempty"`
	// ExitCode is the proc adapter's child exit code (-1 for non-proc paths).
	ExitCode int `json:"exit_code,omitempty"`
}

// Record is one chain entry (design §4.3).
type Record struct {
	Seq       int64      `json:"seq"`
	TS        string     `json:"ts"` // RFC3339Nano, UTC
	RunID     string     `json:"run_id,omitempty"`
	ActionID  string     `json:"action_id,omitempty"`
	Event     string     `json:"event"` // action.executed | gate.decision | ...
	Artifacts []Artifact `json:"artifacts,omitempty"`
	Result    *Result    `json:"result,omitempty"`
	PrevHash  string     `json:"prev_hash,omitempty"`
	Hash      string     `json:"hash,omitempty"`
}

// hashView is the exact struct hashed: everything except Hash itself.
// Field order is part of the hash contract — do not reorder.
type hashView struct {
	Seq       int64      `json:"seq"`
	TS        string     `json:"ts"`
	RunID     string     `json:"run_id,omitempty"`
	ActionID  string     `json:"action_id,omitempty"`
	Event     string     `json:"event"`
	Artifacts []Artifact `json:"artifacts,omitempty"`
	Result    *Result    `json:"result,omitempty"`
	PrevHash  string     `json:"prev_hash,omitempty"`
}

func recordHash(r Record) (string, error) {
	view := hashView{
		Seq:       r.Seq,
		TS:        r.TS,
		RunID:     r.RunID,
		ActionID:  r.ActionID,
		Event:     r.Event,
		Artifacts: r.Artifacts,
		Result:    r.Result,
		PrevHash:  r.PrevHash,
	}
	b, err := jsonMarshal(&view)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:]), nil
}

// HashFile returns the sha256 hex digest of a file's bytes.
func HashFile(path string) (string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("hash file %s: %w", path, err)
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:]), nil
}
