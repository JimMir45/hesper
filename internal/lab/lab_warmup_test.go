package lab

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
)

// TestUpRunsWarmupsAfterHealthy: warmup probes fire after compose reports
// healthy, and provisioning failures fail the Up loudly (M2 live finding:
// VAmPI without /createdb 500s on every user probe).
func TestUpRunsWarmupsAfterHealthy(t *testing.T) {
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if atomic.AddInt32(&hits, 1) < 2 {
			// first attempt 500 → retry must succeed
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	run, _ := fakeRunner(psAllHealthy, nil)
	o := &ComposeOrchestrator{LabRoot: "lab",
		Profiles:     map[string]string{"lite": "compose.lite.yaml"},
		Runner:       run,
		Warmups:      map[string][]WarmupStep{"lite": {{Name: "init", URL: srv.URL}}},
		WarmupClient: srv.Client(),
	}
	h, err := o.Up(context.Background(), "lite")
	if err != nil {
		t.Fatalf("Up with recovering warmup must succeed: %v", err)
	}
	if !h.Healthy {
		t.Fatalf("health wrong: %+v", h)
	}
	if atomic.LoadInt32(&hits) != 2 {
		t.Fatalf("warmup attempts = %d, want 2 (one 500 + retry)", hits)
	}
}

func TestUpFailsLoudlyWhenWarmupKeepsFailing(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	run, _ := fakeRunner(psAllHealthy, nil)
	o := &ComposeOrchestrator{LabRoot: "lab",
		Profiles:     map[string]string{"lite": "compose.lite.yaml"},
		Runner:       run,
		Warmups:      map[string][]WarmupStep{"lite": {{Name: "init", URL: srv.URL}}},
		WarmupClient: srv.Client(),
	}
	if _, err := o.Up(context.Background(), "lite"); err == nil {
		t.Fatal("persistent warmup failure must fail the Up")
	}
}

func TestNilWarmupsSkipWarmup(t *testing.T) {
	run, _ := fakeRunner(psAllHealthy, nil)
	o := &ComposeOrchestrator{LabRoot: "lab",
		Profiles: map[string]string{"lite": "compose.lite.yaml"}, Runner: run,
		WarmupClient: http.DefaultClient,
	}
	if _, err := o.Up(context.Background(), "lite"); err != nil {
		t.Fatalf("nil Warmups must skip warmup: %v", err)
	}
}
