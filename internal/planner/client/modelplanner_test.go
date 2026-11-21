package client

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/JimMir45/hesper/internal/planner"
)

// startStubServer replies with a canned OpenAI-style completion body.
func startStubServer(body string) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(body))
	}))
}

func TestParseProposals(t *testing.T) {
	cases := []struct {
		name    string
		in      string
		want    int
		wantErr bool
	}{
		{"bare array", `[{"card_id":"a","target":"localhost"}]`, 1, false},
		{"fenced", "```json\n[{\"card_id\":\"a\"},{\"card_id\":\"b\"}]\n```", 2, false},
		{"prose-wrapped", "Here is my plan:\n[{\"card_id\":\"a\"}]\nhope this helps", 1, false},
		{"object form", `{"proposals":[{"card_id":"a"}]}`, 1, false},
		{"empty array", `[]`, 0, false},
		{"garbage", "I cannot help with that.", 0, true},
		{"object garbage", `{"error":"confused"}`, 0, true},
	}
	for _, c := range cases {
		ps, err := ParseProposals(c.in)
		if c.wantErr {
			if err == nil {
				t.Errorf("%s: expected error", c.name)
			}
			continue
		}
		if err != nil {
			t.Errorf("%s: %v", c.name, err)
			continue
		}
		if len(ps) != c.want {
			t.Errorf("%s: got %d proposals, want %d", c.name, len(ps), c.want)
		}
	}
}

func TestModelPlannerRoundTrip(t *testing.T) {
	t.Setenv("HESPER_TEST_KEY", "k")
	content := "```json\n" + `[{"card_id":"web-x","target":"localhost","params":{"url":"http://127.0.0.1:5002/x"},"rationale":"probe"}]` + "\n```"
	cj, err := json.Marshal(content)
	if err != nil {
		t.Fatal(err)
	}
	body := `{"choices":[{"message":{"content":` + string(cj) + `}}]}`
	srv := startStubServer(body)
	defer srv.Close()

	mp := NewModelPlanner(New(testModel("openai_compatible", srv.URL+"/v1"), 0, 64), 3)
	ps, err := mp.Next(context.Background(), planner.StateView{Mode: "validate", Turn: 1})
	if err != nil {
		t.Fatalf("Next: %v", err)
	}
	if len(ps) != 1 || ps[0].CardID != "web-x" || ps[0].Params["url"] == "" {
		t.Fatalf("proposals = %+v", ps)
	}
}
