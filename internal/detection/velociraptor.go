package detection

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/JimMir45/hesper/internal/findings"
)

// VeloClient talks to a Velociraptor server through the official CLI:
//
//	velociraptor -a <api-config.yaml> query '<VQL>'  ->  stdout = JSON array of rows
//
// This is the LIVE-VERIFIED contract (M4 live pass, v0.77 server):
//   - Direct HTTP /api/v1/query is gorilla-CSRF-protected for every caller
//     (403 "referer not supplied", then "CSRF token not found"), including
//     valid client certificates; /api/v1/health answers 401 to cert clients.
//   - The supported programmatic path is the CLI with an api-client config
//     minted server-side (`velociraptor --config server.config.yaml config
//     api_client --name <n> --role administrator <out.yaml>`); verified:
//     SELECT Version FROM info() → [{"Version": null}].
//   - Running the AGPL binary as an external process (never linked) is also
//     the license-isolation rule from the action-library research.
//
// The api config yaml carries the client certificate+key; its location is
// referenced by environment variable NAME from run.config (spirit of
// "secrets by env-var name": the operator provisions the file, config never
// holds key material).
type VeloClient struct {
	BinaryPath string // velociraptor CLI binary (default "velociraptor")
	// APIConfigEnv names the env var whose value is the api-config yaml path.
	APIConfigEnv string
	// CommandContext is injectable for tests; defaults to exec.CommandContext.
	CommandContext func(ctx context.Context, name string, arg ...string) *exec.Cmd
}

func (c *VeloClient) cmdFactory() func(ctx context.Context, name string, arg ...string) *exec.Cmd {
	if c.CommandContext != nil {
		return c.CommandContext
	}
	return exec.CommandContext
}

func (c *VeloClient) binary() string {
	if c.BinaryPath == "" {
		return "velociraptor"
	}
	return c.BinaryPath
}

// argv returns the strict argv — no shell, fixed order.
func (c *VeloClient) argv(vql string) []string {
	return []string{c.binary(), "-a", c.apiConfigPath(), "query", vql}
}

func (c *VeloClient) apiConfigPath() string {
	if c.APIConfigEnv == "" {
		return ""
	}
	return os.Getenv(c.APIConfigEnv)
}

type veloRow struct {
	Rule      string `json:"rule"`
	Author    string `json:"author"`
	Level     string `json:"level"`
	Attack    string `json:"attack"`
	Count     int    `json:"count"`
	Timestamp string `json:"timestamp"`
}

// Query runs one VQL statement through the CLI and returns its rows. The CLI
// prints one JSON array (live-verified); a non-zero exit surfaces stderr.
func (c *VeloClient) Query(ctx context.Context, vql string) ([]veloRow, error) {
	cfg := c.apiConfigPath()
	if c.APIConfigEnv != "" && cfg == "" {
		return nil, fmt.Errorf("velociraptor: env %s (api config path) is not set", c.APIConfigEnv)
	}
	factory := c.cmdFactory()
	argv := c.argv(vql)
	cmd := factory(ctx, argv[0], argv[1:]...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("velociraptor: query: %v: %s", err, strings.TrimSpace(stderr.String()))
	}
	out := bytes.TrimSpace(stdout.Bytes())
	if len(out) == 0 {
		return nil, nil
	}
	var rows []veloRow
	if err := json.Unmarshal(out, &rows); err != nil {
		return nil, fmt.Errorf("velociraptor: decode rows: %w", err)
	}
	return rows, nil
}

// Health runs the cheapest query; the CLI exit status is the health signal.
func (c *VeloClient) Health(ctx context.Context) bool {
	_, err := c.Query(ctx, "SELECT * FROM info()")
	return err == nil
}

// VelociraptorJudge is the online detection path (design §5.5).
type VelociraptorJudge struct {
	Client *VeloClient
	// Index supplies attribution for rules the server rows do not carry
	// (fail-closed per DRL-1.1 when neither has the author).
	Index RuleIndex
}

// Correlate queries curated-Sigma hits for the referenced techniques within
// the window. The row shape (rule/author/level/attack/count/timestamp) is
// OUR select-alias contract: the VQL below names the columns, the CLI
// returns them verbatim, the client unmarshals by these keys.
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
