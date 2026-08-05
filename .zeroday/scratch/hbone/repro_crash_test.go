// Reproducer: attempt to crash the REAL hbone.NewServer() process (not just one
// request) via malformed CONNECT targets, stream resets, and concurrency.
// A handler-goroutine panic is recovered by net/http; but handleConnect spawns
// its OWN goroutine that writes to the ResponseWriter, which is NOT covered by
// net/http's per-request recover -> a panic there would crash the process (this
// whole test binary). Run with -race to also surface data races.
//
// go test -race -run Crash -v ./.zeroday/scratch/hbone/
package hbonezeroday

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"
	"testing"
	"time"

	"golang.org/x/net/http2"

	"istio.io/istio/pkg/hbone"
)

func newRealServer(t *testing.T) string {
	t.Helper()
	srv := hbone.NewServer()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	go func() { _ = srv.Serve(l) }()
	t.Cleanup(func() { _ = srv.Close(); l.Close() })
	return l.Addr().String()
}

func rawH2CTransport() *http2.Transport {
	return &http2.Transport{
		AllowHTTP: true,
		DialTLSContext: func(ctx context.Context, network, addr string, _ *tls.Config) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, addr)
		},
	}
}

// TestCrashMalformedTargets throws a batch of hostile CONNECT :authority values
// at the real server and asserts the process stays alive.
func TestCrashMalformedTargets(t *testing.T) {
	server := newRealServer(t)
	tr := rawH2CTransport()

	targets := []string{
		"",                              // empty
		"noport",                        // missing port
		":80",                           // empty host
		"127.0.0.1:99999999",            // absurd port
		"[::1]:0",                       // v6 loopback port 0
		"127.0.0.1:1",                   // closed
		"foo bar:80",                    // space in host
		"127.0.0.1:80\r\nX-Injected: 1", // CRLF injection attempt
		"999.999.999.999:80",            // invalid IP
		string([]byte{0x00, 0x01}) + ":80",
	}
	for _, target := range targets {
		func(target string) {
			pr, pw := io.Pipe()
			req, err := http.NewRequest(http.MethodConnect, "http://"+server, pr)
			if err != nil {
				t.Logf("target=%q build err=%v", target, err)
				return
			}
			req.Host = target
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			req = req.WithContext(ctx)
			resp, err := tr.RoundTrip(req)
			if err != nil {
				t.Logf("target=%q roundtrip err=%v (server survived)", target, err)
				pw.Close()
				return
			}
			t.Logf("target=%q status=%d (server survived)", target, resp.StatusCode)
			resp.Body.Close()
			pw.Close()
		}(target)
	}
	// Liveness probe: a valid CONNECT to a live victim must still work.
	victim := startVictim(t, "ALIVE\n")
	resp, pw, err := h2cConnect(server, victim)
	if err != nil {
		t.Fatalf("server appears dead after malformed inputs: %v", err)
	}
	br := bufio.NewReader(resp.Body)
	got, _ := br.ReadString('\n')
	pw.Close()
	resp.Body.Close()
	t.Logf("post-fuzz liveness OK: %q", got)
}

// TestCrashResetDuringTunnel opens tunnels then abruptly cancels/resets while the
// server goroutine is copying upstream->ResponseWriter, hunting for a write-after-
// reset panic in the uncovered goroutine.
func TestCrashResetDuringTunnel(t *testing.T) {
	server := newRealServer(t)
	// A chatty victim that keeps sending so the server's write goroutine is active.
	l, _ := net.Listen("tcp", "127.0.0.1:0")
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				for i := 0; i < 100000; i++ {
					if _, err := fmt.Fprintf(c, "data-%d-paddddddddddddddddddddddding\n", i); err != nil {
						return
					}
				}
			}(c)
		}
	}()
	defer l.Close()
	victim := l.Addr().String()

	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			tr := rawH2CTransport()
			ctx, cancel := context.WithCancel(context.Background())
			pr, pw := io.Pipe()
			req, _ := http.NewRequest(http.MethodConnect, "http://"+server, pr)
			req.Host = victim
			req = req.WithContext(ctx)
			resp, err := tr.RoundTrip(req)
			if err != nil {
				cancel()
				pw.Close()
				return
			}
			// read a little then abruptly cancel to force RST_STREAM mid-copy
			buf := make([]byte, 64)
			_, _ = resp.Body.Read(buf)
			cancel()
			_ = pw.Close()
			_ = resp.Body.Close()
		}()
	}
	wg.Wait()
	time.Sleep(200 * time.Millisecond)

	// Liveness after the storm.
	victim2 := startVictim(t, "STILL-ALIVE\n")
	resp, pw, err := h2cConnect(server, victim2)
	if err != nil {
		t.Fatalf("server appears dead after reset storm: %v", err)
	}
	br := bufio.NewReader(resp.Body)
	got, _ := br.ReadString('\n')
	pw.Close()
	resp.Body.Close()
	t.Logf("post-reset-storm liveness OK: %q", got)
}
