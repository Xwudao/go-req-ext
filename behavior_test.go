package impersonate_test

import (
	"bufio"
	"bytes"
	"context"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Xwudao/go-req"
	"github.com/Xwudao/go-req-impersonate"
)

func TestHTTP1ResponseTLSState(t *testing.T) {
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "http1")
	}))
	srv.EnableHTTP2 = false
	srv.StartTLS()
	defer srv.Close()
	pool := x509.NewCertPool()
	pool.AddCert(srv.Certificate())

	transport, err := impersonate.New(impersonate.Chrome(), impersonate.WithRootCAs(pool))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(transport.CloseIdleConnections)
	client := &http.Client{Transport: transport}
	resp, err := client.Get(srv.URL)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
	if resp.ProtoMajor != 1 {
		t.Fatalf("proto = %s", resp.Proto)
	}
	if resp.TLS == nil || resp.TLS.NegotiatedProtocol != "http/1.1" {
		t.Fatalf("TLS state = %+v", resp.TLS)
	}
}

func TestStreamingResponse(t *testing.T) {
	release := make(chan struct{})
	var once sync.Once
	t.Cleanup(func() { once.Do(func() { close(release) }) })

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		flusher := w.(http.Flusher)
		_, _ = io.WriteString(w, "first\n")
		flusher.Flush()
		select {
		case <-release:
		case <-r.Context().Done():
			return
		}
		_, _ = io.WriteString(w, "second\n")
		flusher.Flush()
	}))
	defer srv.Close()

	transport, err := impersonate.New(impersonate.Chrome())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(transport.CloseIdleConnections)
	client := &http.Client{Transport: transport}

	resp, err := client.Get(srv.URL)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	defer resp.Body.Close()
	reader := bufio.NewReader(resp.Body)
	line, err := reader.ReadString('\n')
	if err != nil {
		t.Fatalf("read first chunk: %v", err)
	}
	if line != "first\n" {
		t.Fatalf("first = %q", line)
	}
	once.Do(func() { close(release) })
	rest, err := io.ReadAll(reader)
	if err != nil {
		t.Fatalf("read rest: %v", err)
	}
	if string(rest) != "second\n" {
		t.Fatalf("rest = %q", rest)
	}
}

func TestContextCancellation(t *testing.T) {
	t.Run("http1", func(t *testing.T) {
		started := make(chan struct{})
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			close(started)
			<-r.Context().Done()
		}))
		defer srv.Close()

		transport, err := impersonate.New(impersonate.Chrome())
		if err != nil {
			t.Fatalf("New: %v", err)
		}
		t.Cleanup(transport.CloseIdleConnections)
		testContextCancellation(t, &http.Client{Transport: transport}, srv.URL, started)
	})

	t.Run("http2", func(t *testing.T) {
		started := make(chan struct{})
		srv, pool := newHTTPSServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			close(started)
			<-r.Context().Done()
		}))
		transport, err := impersonate.New(impersonate.Chrome(), impersonate.WithRootCAs(pool))
		if err != nil {
			t.Fatalf("New: %v", err)
		}
		t.Cleanup(transport.CloseIdleConnections)
		testContextCancellation(t, &http.Client{Transport: transport}, srv.URL, started)
	})
}

func testContextCancellation(t *testing.T, client *http.Client, target string, started <-chan struct{}) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() {
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
		_, err := client.Do(req)
		errCh <- err
	}()
	select {
	case <-started:
	case <-time.After(3 * time.Second):
		t.Fatal("server did not receive request")
	}
	cancel()
	select {
	case err := <-errCh:
		if err == nil {
			t.Fatal("expected cancellation error")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("request did not stop after cancellation")
	}
}

func TestCoreTimeout(t *testing.T) {
	target, pool := newHTTPSServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-time.After(2 * time.Second):
			_, _ = io.WriteString(w, "late")
		case <-r.Context().Done():
		}
	}))
	transport, err := impersonate.New(impersonate.Chrome(), impersonate.WithRootCAs(pool))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(transport.CloseIdleConnections)
	client := req.New(
		req.WithTransport(transport),
		req.WithTimeout(80*time.Millisecond),
	)

	start := time.Now()
	_, err = client.Get(context.Background(), target.URL).ToString()
	elapsed := time.Since(start)
	if err == nil {
		t.Fatal("expected timeout error")
	}
	if elapsed > time.Second {
		t.Fatalf("timeout took %v", elapsed)
	}
}

func TestRoundTripDoesNotFollowRedirects(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/final" {
			_, _ = io.WriteString(w, "final")
			return
		}
		http.Redirect(w, r, "/final", http.StatusFound)
	}))
	defer srv.Close()

	transport, err := impersonate.New(impersonate.Chrome())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(transport.CloseIdleConnections)
	req, _ := http.NewRequest(http.MethodGet, srv.URL, nil)
	resp, err := transport.RoundTrip(req)
	if err != nil {
		t.Fatalf("RoundTrip: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("status = %d, want 302", resp.StatusCode)
	}
}

func TestConcurrentRequests(t *testing.T) {
	target, pool := newHTTPSServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, r.URL.Query().Get("id"))
	}))
	transport, err := impersonate.New(impersonate.Chrome(), impersonate.WithRootCAs(pool))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(transport.CloseIdleConnections)
	client := &http.Client{Transport: transport}

	const requests = 32
	var wg sync.WaitGroup
	var failures atomic.Int32
	for i := 0; i < requests; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			id := strconv.Itoa(i)
			resp, err := client.Get(target.URL + "?id=" + id)
			if err != nil {
				failures.Add(1)
				return
			}
			body, err := io.ReadAll(resp.Body)
			_ = resp.Body.Close()
			if err != nil || string(body) != id {
				failures.Add(1)
			}
		}(i)
	}
	wg.Wait()
	if failures.Load() != 0 {
		t.Fatalf("%d concurrent requests failed", failures.Load())
	}
}

func TestCloseIdleConnectionsAndReuse(t *testing.T) {
	target, pool := newHTTPSServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "ok")
	}))
	transport, err := impersonate.New(impersonate.Chrome(), impersonate.WithRootCAs(pool))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(transport.CloseIdleConnections)
	client := &http.Client{Transport: transport}
	for i := 0; i < 3; i++ {
		resp, err := client.Get(target.URL)
		if err != nil {
			t.Fatalf("Get %d: %v", i, err)
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
		transport.CloseIdleConnections()
	}
}

func TestResponseTrailers(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Trailer", "X-Checksum")
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, "payload")
		w.Header().Set("X-Checksum", "abc123")
	}))
	defer srv.Close()

	transport, err := impersonate.New(impersonate.Chrome())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(transport.CloseIdleConnections)
	client := &http.Client{Transport: transport}
	resp, err := client.Get(srv.URL)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	_ = resp.Body.Close()
	if string(body) != "payload" {
		t.Fatalf("body = %q", body)
	}
	if got := resp.Trailer.Get("X-Checksum"); got != "abc123" {
		t.Fatalf("trailer = %q", got)
	}
}

func TestRequestBody(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		_, _ = io.WriteString(w, string(body))
	}))
	defer srv.Close()

	transport, err := impersonate.New(impersonate.Chrome())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(transport.CloseIdleConnections)
	client := &http.Client{Transport: transport}
	resp, err := client.Post(srv.URL, "text/plain", strings.NewReader("request-body"))
	if err != nil {
		t.Fatalf("Post: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if string(body) != "request-body" {
		t.Fatalf("body = %q", body)
	}
}

func TestCoreDebugWrapsPluginTransport(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "debug-body")
	}))
	defer srv.Close()

	transport, err := impersonate.New(impersonate.Chrome())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(transport.CloseIdleConnections)
	var output bytes.Buffer
	client := req.New(
		req.WithTransport(transport),
		req.WithDebug(true),
		req.WithDebugWriter(&output),
	)
	body, err := client.Get(context.Background(), srv.URL).ToString()
	if err != nil {
		t.Fatalf("ToString: %v", err)
	}
	if body != "debug-body" {
		t.Fatalf("body = %q", body)
	}
	logged := output.String()
	if !strings.Contains(logged, "GET ") || !strings.Contains(logged, "Status: 200 OK") {
		t.Fatalf("debug output missing request/response: %s", logged)
	}
}

func TestCoreProxyAndDialConflicts(t *testing.T) {
	transport, err := impersonate.New(impersonate.Chrome())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(transport.CloseIdleConnections)

	dial := func(context.Context, string, string) (net.Conn, error) {
		return nil, errors.New("not called")
	}
	tests := []struct {
		name string
		opts []req.Option
	}{
		{name: "core proxy", opts: []req.Option{req.WithTransport(transport), req.WithProxy("http://127.0.0.1:1")}},
		{name: "core dial", opts: []req.Option{req.WithTransport(transport), req.WithDialContext(dial)}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			client, err := req.NewWithOptions(tc.opts...)
			if err == nil || client != nil {
				t.Fatalf("NewWithOptions = (%v, %v), want error", client, err)
			}
			if !errors.Is(err, req.ErrConfiguration) {
				t.Fatalf("err = %v, want ErrConfiguration", err)
			}
		})
	}
}

func TestTLSCertificateVerification(t *testing.T) {
	target, _ := newHTTPSServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "untrusted")
	}))
	transport, err := impersonate.New(impersonate.Chrome())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(transport.CloseIdleConnections)
	client := &http.Client{Transport: transport}
	_, err = client.Get(target.URL)
	if err == nil {
		t.Fatal("expected certificate verification error")
	}
	var unknownAuthority x509.UnknownAuthorityError
	if !errors.As(err, &unknownAuthority) {
		t.Fatalf("err = %T %v, want UnknownAuthorityError", err, err)
	}
}
