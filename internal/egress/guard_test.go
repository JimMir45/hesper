package egress

import (
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/JimMir45/hesper/internal/kernel"
)

func scopeForGuard() *kernel.ScopeManifest {
	return &kernel.ScopeManifest{
		Version: "0.1", Mode: kernel.ModeValidate,
		Targets: []kernel.Target{
			{Kind: "host", Value: "localhost"},
			{Kind: "cidr", Value: "127.0.0.0/8"},
			// ::1 is in scope too: on hosts where IPv4 loopback is unbindable
			// (WSL2 mirrored-mode quirk) the guard and test upstreams bind
			// [::1], and destinations there must stay legitimate.
			{Kind: "host", Value: "::1"},
		},
		Allow:  kernel.Allow{Classes: []string{"web"}, Adapters: []string{"proc"}},
		Budget: kernel.Budget{MaxActions: 5, MaxMinutes: 5},
	}
}

func newStartedGuard(t *testing.T) *Guard {
	t.Helper()
	g, err := NewGuard(scopeForGuard())
	if err != nil {
		t.Fatalf("NewGuard: %v", err)
	}
	g.Start()
	t.Cleanup(func() { _ = g.Close() })
	return g
}

func proxiedClient(addr string) *http.Client {
	return &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			Proxy: func(*http.Request) (*url.URL, error) {
				return url.Parse("http://" + addr)
			},
		},
	}
}

// TestGuardAllowsScopeTarget: an in-scope loopback server is reachable
// THROUGH the guard (plain http, absolute form).
func TestGuardAllowsScopeTarget(t *testing.T) {
	want := "scope-allowed-body"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(want))
	}))
	defer srv.Close()

	g := newStartedGuard(t)
	resp, err := proxiedClient(g.Addr()).Get(srv.URL) // 127.0.0.1:<port>, in scope
	if err != nil {
		t.Fatalf("GET via guard: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status=%d", resp.StatusCode)
	}
	buf := make([]byte, len(want))
	_, _ = resp.Body.Read(buf)
	if string(buf) != want {
		t.Fatalf("body=%q", string(buf))
	}
	if n := g.ViolationCount(); n != 0 {
		t.Fatalf("violations=%d, want 0", n)
	}
}

// TestGuardDeniesOutOfScopeHTTP: TEST-NET-3 documentation address is not in
// scope → 403 + violation recorded with the destination.
func TestGuardDeniesOutOfScopeHTTP(t *testing.T) {
	g := newStartedGuard(t)
	resp, err := proxiedClient(g.Addr()).Get("http://203.0.113.7:80/x")
	if err != nil {
		t.Fatalf("GET via guard: %v (guard must answer, not hang)", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status=%d, want 403", resp.StatusCode)
	}
	v := g.Violations()
	if len(v) != 1 || !strings.HasPrefix(v[0], "203.0.113.7") {
		t.Fatalf("violations=%v, want [203.0.113.7:80]", v)
	}
}

// TestGuardDeniesConnectTunnel: CONNECT to an out-of-scope address is
// refused before any upstream dial, and the violation is recorded.
func TestGuardDeniesConnectTunnel(t *testing.T) {
	g := newStartedGuard(t)
	conn, err := net.DialTimeout("tcp", g.Addr(), 3*time.Second)
	if err != nil {
		t.Fatalf("dial guard: %v", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err := conn.Write([]byte("CONNECT 203.0.113.9:443 HTTP/1.1\r\nHost: 203.0.113.9:443\r\n\r\n")); err != nil {
		t.Fatalf("write CONNECT: %v", err)
	}
	buf := make([]byte, 128)
	n, _ := conn.Read(buf)
	if !strings.Contains(string(buf[:n]), "403") {
		t.Fatalf("CONNECT response=%q, want 403", string(buf[:n]))
	}
	if v := g.Violations(); len(v) != 1 || !strings.HasPrefix(v[0], "203.0.113.9") {
		t.Fatalf("violations=%v", v)
	}
}

// TestGuardAllowsConnectToScope: CONNECT to an in-scope loopback listener
// succeeds (200) and pipes traffic.
func TestGuardAllowsConnectToScope(t *testing.T) {
	ln, err := listenLoopbackRetry()
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		_, _ = c.Write([]byte("tunnel-ok"))
		_ = c.Close()
	}()

	g := newStartedGuard(t)
	conn, err := net.DialTimeout("tcp", g.Addr(), 3*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err := conn.Write([]byte("CONNECT " + authority(ln) + " HTTP/1.1\r\nHost: " + authority(ln) + "\r\n\r\n")); err != nil {
		t.Fatal(err)
	}
	// The 200 response and the tunneled upstream bytes arrive as separate
	// reads — accumulate until both are seen (deadline bounds the wait).
	var got string
	buf := make([]byte, 256)
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		n, rerr := conn.Read(buf)
		if n > 0 {
			got += string(buf[:n])
			if strings.Contains(got, "200") && strings.Contains(got, "tunnel-ok") {
				break
			}
		}
		if rerr != nil {
			break
		}
	}
	if !strings.Contains(got, "200") || !strings.Contains(got, "tunnel-ok") {
		t.Fatalf("CONNECT stream=%q, want 200 + tunnel-ok", got)
	}
	if g.ViolationCount() != 0 {
		t.Fatalf("violations=%d", g.ViolationCount())
	}
}

// TestViolationsSinceSlicesPerAction: the adapter's per-action delta uses
// ViolationSince snapshots.
func TestViolationsSinceSlicesPerAction(t *testing.T) {
	g := newStartedGuard(t)
	before := g.ViolationCount()
	_, _ = proxiedClient(g.Addr()).Get("http://203.0.113.1:80/")
	if got := g.ViolationsSince(before); len(got) != 1 {
		t.Fatalf("delta=%v, want 1 entry", got)
	}
	_, _ = proxiedClient(g.Addr()).Get("http://198.51.100.2:80/")
	if got := g.ViolationsSince(before); len(got) != 2 {
		t.Fatalf("delta=%v, want 2 entries", got)
	}
}

// TestPolicyNilScopeDeniesEverything: fail-closed — nil/absent scope allows
// no destination at all.
func TestPolicyNilScopeDeniesEverything(t *testing.T) {
	var p *Policy
	if p.Allows("localhost") {
		t.Fatal("nil policy must deny")
	}
	if NewPolicy(nil).Allows("localhost") {
		t.Fatal("nil-scope policy must deny")
	}
}

// TestEnvForShapesProxyEnvironment: children get the guard as their proxy,
// with an empty NO_PROXY so nothing is excluded.
func TestEnvForShapesProxyEnvironment(t *testing.T) {
	env := EnvFor("127.0.0.1:45678")
	joined := strings.Join(env, "\n")
	for _, want := range []string{"HTTP_PROXY=http://127.0.0.1:45678", "http_proxy=", "HTTPS_PROXY=", "ALL_PROXY=", "NO_PROXY="} {
		if !strings.Contains(joined, want) {
			t.Fatalf("env missing %s: %v", want, env)
		}
	}
}

// authority returns the listener's full host:port ("127.0.0.1:p" or
// "[::1]:p") — CONNECT-ready for both families.
func authority(ln net.Listener) string { return ln.Addr().String() }

// listenLoopbackRetry: try IPv4 then IPv6 loopback (httptest-style) —
// mirrored-mode WSL can lose IPv4 loopback binding entirely.
func listenLoopbackRetry() (net.Listener, error) {
	var lastErr error
	for _, addr := range []string{"127.0.0.1:0", "[::1]:0"} {
		for i := 0; i < 3; i++ {
			ln, err := net.Listen("tcp", addr)
			if err == nil {
				return ln, nil
			}
			lastErr = err
		}
	}
	return nil, lastErr
}
