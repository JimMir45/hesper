package claims

import (
	"os"
	"path/filepath"
	"testing"
)

func writeClaims(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "claims.json")
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func fakeRunner(codes map[string]int) Runner {
	return func(command, dir string) (int, string, error) {
		if c, ok := codes[command]; ok {
			if c == 0 {
				return 0, "ok", nil
			}
			return c, "boom", nil
		}
		return 0, "default-ok", nil
	}
}

func TestVerifyGreenRedSkip(t *testing.T) {
	p := writeClaims(t, `{
	  "version": "0.1",
	  "claims": [
	    {"id": "C1", "claim": "green one", "command": "echo one"},
	    {"id": "C2", "claim": "red one", "command": "exit 9"},
	    {"id": "L1", "claim": "live one", "command": "echo live", "tier": "live"}
	  ]
	}`)
	res, err := Verify(p, false, fakeRunner(map[string]int{"exit 9": 9}))
	if err != nil {
		t.Fatal(err)
	}
	if len(res) != 3 {
		t.Fatalf("results=%d", len(res))
	}
	if !res[0].OK || res[0].Skipped {
		t.Fatalf("C1: %+v", res[0])
	}
	if res[1].OK {
		t.Fatal("C2 must fail (exit 9)")
	}
	if !res[2].Skipped {
		t.Fatal("L1 must be skipped without withLive")
	}
	summary, allOK := Summary(res)
	if allOK {
		t.Fatal("summary must report failure")
	}
	for _, want := range []string{"[pass] C1", "[FAIL] C2", "[skip] L1", "1 passed, 1 failed, 1 skipped"} {
		if !contains(summary, want) {
			t.Errorf("summary missing %q:\n%s", want, summary)
		}
	}
}

func TestVerifyWithLiveRunsLiveClaims(t *testing.T) {
	p := writeClaims(t, `{
	  "version": "0.1",
	  "claims": [
	    {"id": "L1", "claim": "live one", "command": "echo live", "tier": "live"}
	  ]
	}`)
	res, err := Verify(p, true, fakeRunner(nil))
	if err != nil {
		t.Fatal(err)
	}
	if res[0].Skipped || !res[0].OK {
		t.Fatalf("L1 with --with-live: %+v", res[0])
	}
	if _, allOK := Summary(res); !allOK {
		t.Fatal("all green expected")
	}
}

func TestLoadRejectsBadEntries(t *testing.T) {
	cases := map[string]string{
		"missing command": `{"version":"0.1","claims":[{"id":"X","claim":"c"}]}`,
		"missing id":      `{"version":"0.1","claims":[{"claim":"c","command":"true"}]}`,
		"bad tier":        `{"version":"0.1","claims":[{"id":"X","claim":"c","command":"true","tier":"psychic"}]}`,
	}
	for name, body := range cases {
		if _, err := Load(writeClaims(t, body)); err == nil {
			t.Errorf("%s: expected error", name)
		}
	}
}

func TestExecRunnerRealCommand(t *testing.T) {
	p := writeClaims(t, `{"version":"0.1","claims":[{"id":"R","claim":"real","command":"printf real"}]}`)
	res, err := Verify(p, false, ExecRunner())
	if err != nil {
		t.Fatal(err)
	}
	if !res[0].OK || res[0].Output != "real" {
		t.Fatalf("%+v", res[0])
	}
}

func contains(hay, needle string) bool {
	for i := 0; i+len(needle) <= len(hay); i++ {
		if hay[i:i+len(needle)] == needle {
			return true
		}
	}
	return false
}
