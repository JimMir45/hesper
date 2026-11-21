package detection

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/JimMir45/hesper/internal/findings"
)

// VeloClient talks to a Velociraptor server's HTTP API. The API key is
// referenced by environment variable NAME only (design §4.5) — a key value
// never appears in configuration or files.
//
// Wire contract (ours; the stub server in velociraptor_test.go pins it):
//
//	GET  {base}/api/v1/health            -> 200 when healthy
//	POST {base}/api/v1/query  {"vql":...} -> {"rows":[{"rule":"<name>",
//	                                    "author":"...","level":"...",
//	                                    "attack":"t1003.003",
//	                                    "count":2,"timestamp":"RFC3339"}]}
//
// The rows schema mirrors what a curated-Sigma VQL notebook returns after
// Server.Import.CuratedSigma + Windows.Sigma.EventLogs. Live verification
// against a real Velociraptor is on the M4 live checklist.
type VeloClient struct {
	BaseURL   string
	APIKeyEnv string
	// HTTP is injectable for tests; defaults to http.DefaultClient.
	HTTP *http.Client
}

func (c *VeloClient) httpClient() *http.Client {
	if c.HTTP != nil {
		return c.HTTP
	}
	return http.DefaultClient
}

// Health reports whether the endpoint answers.
func (c *VeloClient) Health(ctx context.Context) bool {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(c.BaseURL, "/")+"/api/v1/health", nil)
	if err != nil {
		return false
	}
	resp, err := c.httpClient().Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	return resp.StatusCode == http.StatusOK
}

type veloQueryRequest struct {
	VQL string `json:"vql"`
}

type veloRow struct {
	Rule      string `json:"rule"`
	Author    string `json:"author"`
	Level     string `json:"level"`
	Attack    string `json:"attack"`
	Count     int    `json:"count"`
	Timestamp string `json:"timestamp"`
}

// Query runs one VQL statement and returns its rows.
func (c *VeloClient) Query(ctx context.Context, vql string) ([]veloRow, error) {
	body, err := json.Marshal(veloQueryRequest{VQL: vql})
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(c.BaseURL, "/")+"/api/v1/query", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	if c.APIKeyEnv != "" {
		if key := os.Getenv(c.APIKeyEnv); key != "" {
			req.Header.Set("Authorization", "Bearer "+key)
		}
	}
	resp, err := c.httpClient().Do(req)
	if err != nil {
		return nil, fmt.Errorf("velociraptor: query: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("velociraptor: query: status %d", resp.StatusCode)
	}
	var out struct {
		Rows []veloRow `json:"rows"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 32<<20)).Decode(&out); err != nil {
		return nil, fmt.Errorf("velociraptor: decode: %w", err)
	}
	return out.Rows, nil
}

// VelociraptorJudge is the online detection path (design §5.5).
type VelociraptorJudge struct {
	Client *VeloClient
	// Index supplies attribution for rules the server rows do not carry
	// (fail-closed per DRL-1.1 when neither has the author).
	Index RuleIndex
}

// Correlate queries curated-Sigma hits for the referenced techniques within
// the window. Server-side filtering is by attack tag + timestamp range;
// client-side filtering is defense in depth.
func (v *VelociraptorJudge) Correlate(ctx context.Context, w Window, refs []ActionRef) ([]findings.Hit, error) {
	techs := map[string]bool{}
	for _, r := range refs {
		techs[strings.ToLower(r.AttackID)] = true
	}
	var quoted []string
	for t := range techs {
		quoted = append(quoted, fmt.Sprintf("%q", t))
	}
	vql := fmt.Sprintf(
		"SELECT rule, author, level, attack, count(value) AS count, timestamp "+
			"FROM sigma_hits() WHERE attack IN (%s) AND timestamp >= from_epoch(%d) AND timestamp <= to_epoch(%d) GROUP BY rule",
		strings.Join(quoted, ", "), w.From.UnixMilli(), w.To.UnixMilli())
	rows, err := v.Client.Query(ctx, vql)
	if err != nil {
		return nil, err
	}

	hits := make([]findings.Hit, 0, len(rows))
	for _, row := range rows {
		if row.Rule == "" {
			continue
		}
		if row.Timestamp != "" {
			if t, err := time.Parse(time.RFC3339, row.Timestamp); err == nil && (t.Before(w.From) || t.After(w.To)) {
				continue
			}
		}
		author := row.Author
		if author == "" {
			author = v.Index[row.Rule].Author
		}
		if author == "" {
			return nil, fmt.Errorf("velociraptor judge: rule %q missing author (DRL-1.1 fail-closed)", row.Rule)
		}
		level := row.Level
		if level == "" {
			level = v.Index[row.Rule].Level
		}
		n := row.Count
		if n == 0 {
			n = 1
		}
		hits = append(hits, findings.Hit{RuleID: row.Rule, Author: author, Level: level, Matches: n})
	}
	sortHits(hits)
	return hits, nil
}
