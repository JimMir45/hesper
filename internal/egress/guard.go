// Package egress implements runtime egress enforcement (design §7, M4+
// hardening layer): a local control proxy that carries child-process traffic
// and refuses destinations outside the scope manifest, turning "adapters
// egress only toward in-scope targets" from a type-level promise into
// network-level interception.
//
// Enforcement is honest about its reach (ARTEX lesson: claims must match
// reality):
//
//	LevelProxy    — proc children run with proxy env pointing at the Guard;
//	                proxy-AWARE clients (curl, wget, most scanners) are
//	                intercepted. Proxy-unaware raw sockets bypass it; full
//	                coverage would need netns/LD_PRELOAD, which is not
//	                portable across the WSL/Windows-host matrix.
//	LevelDeclared — vm adapter: the policy is declared and audited, but VM
//	                traffic does not traverse the host process stack, so this
//	                level is declaration + audit, not interception.
//	LevelNone     — no runtime enforcement (kernel type discipline only).
//
// Every action reports which level actually applied (audit event
// egress.enforcement), so reports never claim more than was enforced.
package egress

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"

	"github.com/JimMir45/hesper/internal/kernel"
)

// Enforcement levels (design §7 enforcement matrix).
const (
	LevelProxy    = "proxy"
	LevelDeclared = "declared+audit"
	LevelNone     = "none"
)

// Policy decides which destinations are reachable: exactly the scope
// manifest's targets, nothing else.
type Policy struct {
	scope *kernel.ScopeManifest
}

func NewPolicy(s *kernel.ScopeManifest) *Policy { return &Policy{scope: s} }

// Allows reports whether host (a hostname or IP, no port) is an in-scope
// target. Matching reuses the kernel's fail-closed target gate.
func (p *Policy) Allows(host string) bool {
	if p == nil || p.scope == nil {
		return false
	}
	return p.scope.TargetInScope(host)
}

// Guard is the local control proxy. Serve runs until Close; violations are
// recorded with the destination and surfaced to the adapter per action.
type Guard struct {
	ln     net.Listener
	policy *Policy

	mu         sync.Mutex
	violations []string
	closed     bool
}

// NewGuard binds the proxy on a loopback ephemeral port for the given scope.
// Call Start to serve and Close when the run ends.
//
// Bind strategy mirrors net/http/httptest's local listener: try IPv4
// loopback first, fall back to IPv6 loopback. On WSL2 mirrored networking
// the IPv4 loopback port space is shared with the Windows host and can
// become wholly unbindable (observed live: every 127.0.0.1:0 bind returns
// EADDRINUSE); [::1] keeps working. A couple of retries per family absorb
// transient ephemeral collisions.
func NewGuard(s *kernel.ScopeManifest) (*Guard, error) {
	families := []string{"127.0.0.1:0", "[::1]:0"}
	var lastErr error
	for _, addr := range families {
		for attempt := 0; attempt < 3; attempt++ {
			ln, err := net.Listen("tcp", addr)
			if err == nil {
				return &Guard{ln: ln, policy: NewPolicy(s)}, nil
			}
			lastErr = err
		}
	}
	return nil, fmt.Errorf("egress: listen (loopback v4+v6): %w", lastErr)
}

// Addr is the proxy address to hand to child processes.
func (g *Guard) Addr() string { return g.ln.Addr().String() }

// Start serves connections in the background until Close.
func (g *Guard) Start() {
	go func() {
		for {
			conn, err := g.ln.Accept()
			if err != nil {
				return // listener closed
			}
			go g.handle(conn)
		}
	}()
}

// Close shuts the listener down.
func (g *Guard) Close() error {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.closed {
		return nil
	}
	g.closed = true
	return g.ln.Close()
}

// ViolationCount is the total violations seen so far (adapter deltas use it).
func (g *Guard) ViolationCount() int {
	g.mu.Lock()
	defer g.mu.Unlock()
	return len(g.violations)
}

// Violations returns a copy of all recorded destinations.
func (g *Guard) Violations() []string {
	g.mu.Lock()
	defer g.mu.Unlock()
	out := make([]string, len(g.violations))
	copy(out, g.violations)
	return out
}

// ViolationsSince returns destinations recorded after the first n events —
// the per-action slice between two snapshots.
func (g *Guard) ViolationsSince(n int) []string {
	g.mu.Lock()
	defer g.mu.Unlock()
	if n < 0 {
		n = 0
	}
	if n > len(g.violations) {
		return nil
	}
	out := make([]string, len(g.violations)-n)
	copy(out, g.violations[n:])
	return out
}

func (g *Guard) record(dest string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.violations = append(g.violations, dest)
}

func hostOnly(hostPort string) string {
	if h, _, err := net.SplitHostPort(hostPort); err == nil {
		return h
	}
	return hostPort
}

// handle serves one child connection: CONNECT (tunnel) or absolute-form HTTP.
func (g *Guard) handle(conn net.Conn) {
	defer conn.Close()
	br := bufio.NewReader(conn)
	req, err := http.ReadRequest(br)
	if err != nil {
		return
	}
	if req.Method == http.MethodConnect {
		g.tunnel(conn, req)
		return
	}
	g.forward(conn, req)
}

// tunnel handles CONNECT host:port — the https path of proxy-aware clients.
func (g *Guard) tunnel(conn net.Conn, req *http.Request) {
	dest := req.URL.Host
	if !g.policy.Allows(hostOnly(dest)) {
		g.record(dest)
		fmt.Fprintf(conn, "HTTP/1.1 403 Forbidden (egress: destination outside scope)\r\nContent-Length: 0\r\n\r\n")
		return
	}
	upstream, err := net.Dial("tcp", dest)
	if err != nil {
		fmt.Fprintf(conn, "HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
		return
	}
	defer upstream.Close()
	fmt.Fprintf(conn, "HTTP/1.1 200 Connection Established\r\n\r\n")
	pipe(conn, upstream)
}

// forward handles absolute-form http:// requests (plain http via proxy).
func (g *Guard) forward(conn net.Conn, req *http.Request) {
	dest := req.URL.Host
	if !g.policy.Allows(hostOnly(dest)) {
		g.record(dest)
		resp := &http.Response{
			StatusCode: http.StatusForbidden,
			Status:     "403 egress: destination outside scope",
			Proto:      "HTTP/1.1", ProtoMajor: 1, ProtoMinor: 1,
			Header: make(http.Header), Body: io.NopCloser(strings.NewReader("egress denied: destination outside scope\n")),
			Request: req,
		}
		_ = resp.Write(conn)
		return
	}
	upstream, err := net.Dial("tcp", dest)
	if err != nil {
		resp := &http.Response{
			StatusCode: http.StatusBadGateway, Status: "502 Bad Gateway",
			Proto: "HTTP/1.1", ProtoMajor: 1, ProtoMinor: 1,
			Header: make(http.Header), Body: io.NopCloser(strings.NewReader("upstream unreachable\n")),
			Request: req,
		}
		_ = resp.Write(conn)
		return
	}
	defer upstream.Close()
	// Replay the request line with the absolute URL, then pipe both ways.
	// Header.Write omits the Host field (it lives in req.Host), so the Host
	// header is written explicitly — a missing Host is a 400 at any Go
	// upstream server.
	fmt.Fprintf(upstream, "%s %s %s\r\n", req.Method, req.URL.String(), req.Proto)
	host := req.Host
	if host == "" {
		host = req.URL.Host
	}
	fmt.Fprintf(upstream, "Host: %s\r\n", host)
	if err := req.Header.Write(upstream); err != nil {
		return
	}
	fmt.Fprint(upstream, "\r\n")
	pipe(conn, upstream)
}

func pipe(a, b net.Conn) {
	done := make(chan struct{}, 2)
	cp := func(from, to net.Conn) {
		_, _ = io.Copy(to, from)
		done <- struct{}{}
	}
	go cp(a, b)
	go cp(b, a)
	<-done
}

// EnvFor returns proxy environment variables pointing children at the guard.
// Paired with NO_PROXY="" so nothing escapes by exclusion list.
func EnvFor(addr string) []string {
	proxy := "http://" + addr
	return []string{
		"HTTP_PROXY=" + proxy, "http_proxy=" + proxy,
		"HTTPS_PROXY=" + proxy, "https_proxy=" + proxy,
		"ALL_PROXY=" + proxy, "all_proxy=" + proxy,
		"NO_PROXY=", "no_proxy=",
	}
}

// ParseDestHost extracts the host (no port) from a URL or host:port string —
// helper for tests and diagnostics.
func ParseDestHost(dest string) string {
	if u, err := url.Parse(dest); err == nil && u.Host != "" {
		return hostOnly(u.Host)
	}
	return hostOnly(dest)
}
