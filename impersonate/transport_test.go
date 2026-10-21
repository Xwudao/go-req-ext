package impersonate_test

import (
	"context"
	"crypto/x509"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Xwudao/go-req"
	"github.com/Xwudao/go-req-ext/impersonate"
)

func newHTTPSServer(t *testing.T, handler http.Handler) (*httptest.Server, *x509.CertPool) {
	t.Helper()
	srv := httptest.NewUnstartedServer(handler)
	srv.Config.ErrorLog = log.New(io.Discard, "", 0)
	srv.EnableHTTP2 = true
	srv.StartTLS()
	t.Cleanup(srv.Close)
	pool := x509.NewCertPool()
	pool.AddCert(srv.Certificate())
	return srv, pool
}

func TestBasicHTTPSHTTP2(t *testing.T) {
	srv, pool := newHTTPSServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "hello")
	}))
	transport, err := impersonate.New(impersonate.Chrome(), impersonate.WithRootCAs(pool))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(transport.CloseIdleConnections)
	client := req.New(req.WithTransport(transport))
	resp, err := client.Get(context.Background(), srv.URL).Do()
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if string(body) != "hello" {
		t.Fatalf("body=%q", body)
	}
	if resp.ProtoMajor != 2 {
		t.Fatalf("proto=%s", resp.Proto)
	}
	if resp.TLS == nil || resp.TLS.NegotiatedProtocol != "h2" {
		t.Fatalf("tls=%+v", resp.TLS)
	}
}
