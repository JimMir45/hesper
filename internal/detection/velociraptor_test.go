package detection

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/JimMir45/hesper/internal/findings"
)

func TestVelociraptorJudgeContract(t *testing.T) {
	var gotAuth, gotVQL string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/health":
			w.WriteHeader(http.StatusOK)
		case "/api/v1/query":
			gotAuth = r.Header.Get("Authorization")
			var body struct{ VQL string }
			_ = json.NewDecoder(r.Body).Decode(&body)
			gotVQL = body.VQL
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"rows":[
				{"rule":"Invocation of Active Directory Diagnostic Tool (ntdsutil.exe)","author":"Thomas Patzke","level":"medium","attack":"t1003.003","count":3,"timestamp":"2026-11-21T10:00:10Z"},
				{"rule":"Suspicious Process Patterns NTDS.DIT Exfil","author":"","level":"","attack":"t1003.003","count":1,"timestamp":"2026-11-21T10:00:20Z"}
			]}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	t.Setenv("HESPER_VELO_KEY", "secret-token-123")
	client := &VeloClient{BaseURL: srv.URL, APIKeyEnv: "HESPER_VELO_KEY", HTTP: srv.Client()}
	if !client.Health(context.Background()) {
		t.Fatal("health must be true against stub")
	}

	j := &VelociraptorJudge{Client: client, Index: RuleIndex{
		"Suspicious Process Patterns NTDS.DIT Exfil": {Author: "Florian Roth (Nextron Systems)", Level: "high"},
	}}
	w := Window{From: ts("2026-11-21T10:00:00Z"), To: ts("2026-11-21T10:02:00Z")}
	refs := []ActionRef{{ID: "a1", AttackID: "T1003.003", TS: ts("2026-11-21T10:00:05Z")}}

	hits, err := j.Correlate(context.Background(), w, refs)
	if err != nil {
		t.Fatalf("Correlate: %v", err)
	}
	if len(hits) != 2 {
		t.Fatalf("want 2 hits, got %+v", hits)
	}
	if gotAuth != "Bearer secret-token-123" {
		t.Fatalf("api key by env name not sent: %q", gotAuth)
	}
	if !strings.Contains(gotVQL, `"t1003.003"`) {
		t.Fatalf("VQL must filter on the technique join key: %q", gotVQL)
	}
	byRule := hitMap(hits)
	if byRule["Invocation of Active Directory Diagnostic Tool (ntdsutil.exe)"].Matches != 3 {
		t.Fatalf("match count wrong: %+v", hits)
	}
	// Row without author falls back to the index (DRL-1.1).
	if byRule["Suspicious Process Patterns NTDS.DIT Exfil"].Author != "Florian Roth (Nextron Systems)" {
		t.Fatalf("index author fallback failed: %+v", hits)
	}
}

func TestVelociraptorJudgeAttributionFailClosed(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/query" {
			_, _ = w.Write([]byte(`{"rows":[{"rule":"Ghost Rule","attack":"t1003.003","count":1,"timestamp":"2026-11-21T10:00:10Z"}]}`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	j := &VelociraptorJudge{Client: &VeloClient{BaseURL: srv.URL, HTTP: srv.Client()}}
	w := Window{From: ts("2026-11-21T10:00:00Z"), To: ts("2026-11-21T10:02:00Z")}
	refs := []ActionRef{{ID: "a1", AttackID: "T1003.003", TS: ts("2026-11-21T10:00:05Z")}}
	if _, err := j.Correlate(context.Background(), w, refs); err == nil {
		t.Fatal("hit without any author source must be a hard error")
	}
}

func TestAutoJudgePicksHealthyPath(t *testing.T) {
	onlineSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/health" {
			w.WriteHeader(http.StatusOK)
			return
		}
		if r.URL.Path == "/api/v1/query" {
			_, _ = w.Write([]byte(`{"rows":[{"rule":"Online Rule","author":"A","attack":"t1003.003","count":1,"timestamp":"2026-11-21T10:00:10Z"}]}`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer onlineSrv.Close()

	offline := offlineJudge(`{"timestamp":"2026-11-21T10:00:05Z","name":"Offline Rule","level":"high","tags":["attack.t1003.003"]}`)
	offline.Index = RuleIndex{"Offline Rule": {Author: "B"}}
	auto := &AutoJudge{
		Online:  &VelociraptorJudge{Client: &VeloClient{BaseURL: onlineSrv.URL, HTTP: onlineSrv.Client()}},
		Offline: offline,
	}
	w := Window{From: ts("2026-11-21T10:00:00Z"), To: ts("2026-11-21T10:02:00Z")}
	refs := []ActionRef{{ID: "a1", AttackID: "T1003.003", TS: ts("2026-11-21T10:00:05Z")}}

	hits, err := auto.Correlate(context.Background(), w, refs)
	if err != nil {
		t.Fatalf("Correlate: %v", err)
	}
	if auto.LastPath() != "velociraptor" || len(hits) != 1 || hits[0].RuleID != "Online Rule" {
		t.Fatalf("online path not used: path=%s hits=%+v", auto.LastPath(), hits)
	}

	// Server dies -> auto falls back offline.
	onlineSrv.Close()
	hits, err = auto.Correlate(context.Background(), w, refs)
	if err != nil {
		t.Fatalf("Correlate offline fallback: %v", err)
	}
	if auto.LastPath() != "offline" || len(hits) != 1 || hits[0].RuleID != "Offline Rule" {
		t.Fatalf("offline fallback not used: path=%s hits=%+v", auto.LastPath(), hits)
	}
}

func hitMap(hits []findings.Hit) map[string]findings.Hit {
	m := make(map[string]findings.Hit, len(hits))
	for _, h := range hits {
		m[h.RuleID] = h
	}
	return m
}
