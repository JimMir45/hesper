package evidence

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// jsonMarshal is split out so the hash contract is explicit and stable.
func jsonMarshal(v any) ([]byte, error) {
	return json.Marshal(v)
}

const chainFile = "chain.jsonl"

// Chain is the append-only writer for one run's evidence/chain.jsonl.
// Single writer in production (the run loop); mutex-guarded defensively.
type Chain struct {
	mu       sync.Mutex
	path     string // absolute path to chain.jsonl
	runDir   string
	seq      int64
	prevHash string
}

// OpenChain opens (creating if needed) the chain of a run directory,
// resuming seq/prevHash from any existing records.
func OpenChain(runDir string) (*Chain, error) {
	dir := filepath.Join(runDir, "evidence")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, fmt.Errorf("evidence: mkdir %s: %w", dir, err)
	}
	c := &Chain{
		path:   filepath.Join(dir, chainFile),
		runDir: runDir,
	}
	// Resume: replay existing lines for seq and prev hash.
	f, err := os.Open(c.path)
	if err == nil {
		defer f.Close()
		sc := bufio.NewScanner(f)
		sc.Buffer(make([]byte, 0, 1024*1024), 16*1024*1024)
		for sc.Scan() {
			var r Record
			if err := json.Unmarshal(sc.Bytes(), &r); err != nil {
				return nil, fmt.Errorf("evidence: corrupt chain %s: %w", c.path, err)
			}
			if r.Seq > c.seq {
				c.seq = r.Seq
			}
			c.prevHash = r.Hash
		}
		if err := sc.Err(); err != nil {
			return nil, fmt.Errorf("evidence: scan %s: %w", c.path, err)
		}
	} else if !os.IsNotExist(err) {
		return nil, fmt.Errorf("evidence: open %s: %w", c.path, err)
	}
	return c, nil
}

// Append links the record onto the chain tail and writes it as one JSONL
// line. Seq/TS are filled when empty; PrevHash/Hash are always set here.
func (c *Chain) Append(r Record) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.seq++
	if r.TS == "" {
		r.TS = time.Now().UTC().Format(time.RFC3339Nano)
	}
	r.Seq = c.seq
	r.PrevHash = c.prevHash
	// Artifact integrity at append time: any artifact without a hash gets
	// hashed NOW against the file on disk (adapters that pre-hash keep their
	// value; verify re-checks both cases). A missing file is an error here —
	// evidence must be complete at the moment of chaining, not at verify.
	runDir := filepath.Dir(filepath.Dir(c.path))
	for i := range r.Artifacts {
		if r.Artifacts[i].SHA256 == "" {
			sum, err := HashFile(filepath.Join(runDir, filepath.FromSlash(r.Artifacts[i].Path)))
			if err != nil {
				c.seq--
				return "", fmt.Errorf("evidence: hash artifact %s: %w", r.Artifacts[i].Path, err)
			}
			r.Artifacts[i].SHA256 = sum
		}
	}
	hash, err := recordHash(r)
	if err != nil {
		c.seq--
		return "", fmt.Errorf("evidence: hash: %w", err)
	}
	r.Hash = hash
	b, err := jsonMarshal(&r)
	if err != nil {
		c.seq--
		return "", fmt.Errorf("evidence: marshal: %w", err)
	}
	f, err := os.OpenFile(c.path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		c.seq--
		return "", fmt.Errorf("evidence: open %s: %w", c.path, err)
	}
	defer f.Close()
	if _, err := f.WriteString(string(b) + "\n"); err != nil {
		c.seq--
		return "", fmt.Errorf("evidence: write: %w", err)
	}
	c.prevHash = hash
	return hash, nil
}

// verifyRecord checks one record's hash and its artifacts' bytes.
// runDir resolves artifact paths; prevHash is the expected previous hash.
func verifyRecord(runDir string, r Record, prevHash string) error {
	if r.Seq <= 0 {
		return fmt.Errorf("record %d: bad seq", r.Seq)
	}
	if r.PrevHash != prevHash {
		return fmt.Errorf("record %d: prev_hash mismatch (chain broken)", r.Seq)
	}
	want, err := recordHash(r)
	if err != nil {
		return fmt.Errorf("record %d: hash: %w", r.Seq, err)
	}
	if want != r.Hash {
		return fmt.Errorf("record %d: hash mismatch (record tampered)", r.Seq)
	}
	for _, a := range r.Artifacts {
		p := filepath.Join(runDir, filepath.FromSlash(a.Path))
		got, err := HashFile(p)
		if err != nil {
			return fmt.Errorf("record %d: artifact %s: %w", r.Seq, a.Path, err)
		}
		if got != a.SHA256 {
			return fmt.Errorf("record %d: artifact %s: sha256 mismatch (file tampered)", r.Seq, a.Path)
		}
	}
	return nil
}

// Verify recomputes the full chain of a run directory: linkage, record
// hashes, and artifact bytes. A tampered run cannot pass.
func Verify(runDir string) error {
	path := filepath.Join(runDir, "evidence", chainFile)
	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("evidence verify: open %s: %w", path, err)
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 1024*1024), 16*1024*1024)
	prev := ""
	n := 0
	for sc.Scan() {
		n++
		var r Record
		if err := json.Unmarshal(sc.Bytes(), &r); err != nil {
			return fmt.Errorf("evidence verify: line %d not valid JSON: %w", n, err)
		}
		if err := verifyRecord(runDir, r, prev); err != nil {
			return fmt.Errorf("evidence verify: %w", err)
		}
		prev = r.Hash
	}
	if err := sc.Err(); err != nil {
		return fmt.Errorf("evidence verify: scan: %w", err)
	}
	if n == 0 {
		return fmt.Errorf("evidence verify: empty chain in %s", runDir)
	}
	return nil
}

// Tail returns the last n records of a run's chain (planner context policy
// input, design §5.4). Fewer records are returned when the chain is short.
func Tail(runDir string, n int) ([]Record, error) {
	path := filepath.Join(runDir, "evidence", chainFile)
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("evidence tail: read %s: %w", path, err)
	}
	var all []Record
	for _, line := range splitLines(b) {
		var r Record
		if err := json.Unmarshal(line, &r); err != nil {
			return nil, fmt.Errorf("evidence tail: parse: %w", err)
		}
		all = append(all, r)
	}
	if n < 0 {
		n = 0
	}
	if len(all) > n {
		all = all[len(all)-n:]
	}
	return all, nil
}

func splitLines(b []byte) [][]byte {
	var out [][]byte
	start := 0
	for i, c := range b {
		if c == '\n' {
			if i > start {
				out = append(out, b[start:i])
			}
			start = i + 1
		}
	}
	if start < len(b) {
		out = append(out, b[start:])
	}
	return out
}
