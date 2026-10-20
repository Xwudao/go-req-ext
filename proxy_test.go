package impersonate_test

import (
	"bufio"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Xwudao/go-req-impersonate"
)

type httpProxy struct {
	server   *httptest.Server
	username string
	password string

	mu       sync.Mutex
	targets  []string
	authSeen []string
}

func newHTTPProxy(t *testing.T, useTLS bool, username, password string) *httpProxy {
	t.Helper()
	p := &httpProxy{username: username, password: password}
	handler := http.HandlerFunc(p.handle)
	if useTLS {
		p.server = httptest.NewTLSServer(handler)
	} else {
		p.server = httptest.NewServer(handler)
	}
	t.Cleanup(p.server.Close)
	return p
}

func (p *httpProxy) handle(w http.ResponseWriter, r *http.Request) {
	auth := r.Header.Get("Proxy-Authorization")
	p.mu.Lock()
	p.authSeen = append(p.authSeen, auth)
	p.mu.Unlock()

	if p.username != "" || p.password != "" {
		want := "Basic " + base64.StdEncoding.EncodeToString([]byte(p.username+":"+p.password))
		if auth != want {
			w.Header().Set("Proxy-Authenticate", `Basic realm="test"`)
			http.Error(w, "proxy authentication required", http.StatusProxyAuthRequired)
			return
		}
	}
	if r.Method != http.MethodConnect {
		http.Error(w, "CONNECT required", http.StatusMethodNotAllowed)
		return
	}

	p.mu.Lock()
	p.targets = append(p.targets, r.Host)
	p.mu.Unlock()

	destination, err := net.DialTimeout("tcp", r.Host, 5*time.Second)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	defer destination.Close()
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "hijacking unsupported", http.StatusInternalServerError)
		return
	}
	client, _, err := hijacker.Hijack()
	if err != nil {
		return
	}
	defer client.Close()
	if _, err := io.WriteString(client, "HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
		return
	}
	done := make(chan struct{}, 2)
	go func() { _, _ = io.Copy(destination, client); done <- struct{}{} }()
	go func() { _, _ = io.Copy(client, destination); done <- struct{}{} }()
	<-done
}

func (p *httpProxy) targetCount() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.targets)
}

func (p *httpProxy) lastAuth() string {
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(p.authSeen) == 0 {
		return ""
	}
	return p.authSeen[len(p.authSeen)-1]
}

func proxyWithCredentials(t *testing.T, raw, username, password string) string {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("parse proxy URL: %v", err)
	}
	u.User = url.UserPassword(username, password)
	return u.String()
}

func TestHTTPProxyCONNECT(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "through-http-proxy")
	}))
	defer target.Close()
	proxy := newHTTPProxy(t, false, "", "")

	transport, err := impersonate.New(impersonate.Chrome(), impersonate.WithProxy(proxy.server.URL))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(transport.CloseIdleConnections)

	client := &http.Client{Transport: transport}
	resp, err := client.Get(target.URL)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if string(body) != "through-http-proxy" {
		t.Fatalf("body = %q", body)
	}
	if proxy.targetCount() != 1 {
		t.Fatalf("proxy CONNECT count = %d", proxy.targetCount())
	}
}

func TestHTTPSProxyCONNECT(t *testing.T) {
	target, pool := newHTTPSServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "through-https-proxy")
	}))
	proxy := newHTTPProxy(t, true, "", "")
	pool.AddCert(proxy.server.Certificate())

	transport, err := impersonate.New(
		impersonate.Chrome(),
		impersonate.WithProxy(proxy.server.URL),
		impersonate.WithRootCAs(pool),
	)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(transport.CloseIdleConnections)

	client := &http.Client{Transport: transport}
	resp, err := client.Get(target.URL)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if string(body) != "through-https-proxy" {
		t.Fatalf("body = %q", body)
	}
	if resp.ProtoMajor != 2 {
		t.Fatalf("proto = %s", resp.Proto)
	}
}

func TestHTTPProxyAuthentication(t *testing.T) {
	const username = "proxy-user"
	const password = "proxy-pass"

	target, pool := newHTTPSServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "authenticated")
	}))
	proxy := newHTTPProxy(t, false, username, password)

	transport, err := impersonate.New(
		impersonate.Chrome(),
		impersonate.WithProxy(proxyWithCredentials(t, proxy.server.URL, username, password)),
		impersonate.WithRootCAs(pool),
	)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(transport.CloseIdleConnections)

	client := &http.Client{Transport: transport}
	resp, err := client.Get(target.URL)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	want := "Basic " + base64.StdEncoding.EncodeToString([]byte(username+":"+password))
	if got := proxy.lastAuth(); got != want {
		t.Fatalf("Proxy-Authorization = %q, want %q", got, want)
	}
}

type socksProxy struct {
	listener net.Listener
	username string
	password string

	mu      sync.Mutex
	targets []string
}

func newSOCKSProxy(t *testing.T, username, password string) *socksProxy {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	p := &socksProxy{listener: listener, username: username, password: password}
	go p.serve()
	t.Cleanup(func() { _ = listener.Close() })
	return p
}

func (p *socksProxy) url() string {
	host, port, _ := net.SplitHostPort(p.listener.Addr().String())
	u := &url.URL{Scheme: "socks5", Host: net.JoinHostPort(host, port)}
	if p.username != "" {
		u.User = url.UserPassword(p.username, p.password)
	}
	return u.String()
}

func (p *socksProxy) serve() {
	for {
		conn, err := p.listener.Accept()
		if err != nil {
			return
		}
		go p.handle(conn)
	}
}

func (p *socksProxy) handle(conn net.Conn) {
	defer conn.Close()
	reader := bufio.NewReader(conn)
	header := make([]byte, 2)
	if _, err := io.ReadFull(reader, header); err != nil || header[0] != 5 {
		return
	}
	methods := make([]byte, int(header[1]))
	if _, err := io.ReadFull(reader, methods); err != nil {
		return
	}
	method := byte(0)
	if p.username != "" {
		method = 2
		if !containsByte(methods, 2) {
			_, _ = conn.Write([]byte{5, 0xff})
			return
		}
	}
	if _, err := conn.Write([]byte{5, method}); err != nil {
		return
	}
	if method == 2 {
		version := make([]byte, 2)
		if _, err := io.ReadFull(reader, version); err != nil || version[0] != 1 {
			return
		}
		username := make([]byte, int(version[1]))
		if _, err := io.ReadFull(reader, username); err != nil {
			return
		}
		length := make([]byte, 1)
		if _, err := io.ReadFull(reader, length); err != nil {
			return
		}
		password := make([]byte, int(length[0]))
		if _, err := io.ReadFull(reader, password); err != nil {
			return
		}
		if string(username) != p.username || string(password) != p.password {
			_, _ = conn.Write([]byte{1, 1})
			return
		}
		if _, err := conn.Write([]byte{1, 0}); err != nil {
			return
		}
	}

	request := make([]byte, 4)
	if _, err := io.ReadFull(reader, request); err != nil || request[0] != 5 || request[1] != 1 {
		return
	}
	host, err := readSOCKSAddr(reader, request[3])
	if err != nil {
		return
	}
	portBytes := make([]byte, 2)
	if _, err := io.ReadFull(reader, portBytes); err != nil {
		return
	}
	target := net.JoinHostPort(host, strconv.Itoa(int(binary.BigEndian.Uint16(portBytes))))
	p.mu.Lock()
	p.targets = append(p.targets, target)
	p.mu.Unlock()

	destination, err := net.DialTimeout("tcp", target, 5*time.Second)
	if err != nil {
		_, _ = conn.Write([]byte{5, 1, 0, 1, 0, 0, 0, 0, 0, 0})
		return
	}
	defer destination.Close()
	if _, err := conn.Write([]byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0}); err != nil {
		return
	}
	done := make(chan struct{}, 2)
	go func() { _, _ = io.Copy(destination, reader); done <- struct{}{} }()
	go func() { _, _ = io.Copy(conn, destination); done <- struct{}{} }()
	<-done
}

func (p *socksProxy) targetCount() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.targets)
}

func readSOCKSAddr(reader io.Reader, addressType byte) (string, error) {
	switch addressType {
	case 1:
		raw := make([]byte, 4)
		_, err := io.ReadFull(reader, raw)
		return net.IP(raw).String(), err
	case 3:
		length := make([]byte, 1)
		if _, err := io.ReadFull(reader, length); err != nil {
			return "", err
		}
		raw := make([]byte, int(length[0]))
		_, err := io.ReadFull(reader, raw)
		return string(raw), err
	case 4:
		raw := make([]byte, 16)
		_, err := io.ReadFull(reader, raw)
		return net.IP(raw).String(), err
	default:
		return "", fmt.Errorf("unknown SOCKS address type %d", addressType)
	}
}

func containsByte(values []byte, target byte) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

func TestSOCKS5Proxy(t *testing.T) {
	target, pool := newHTTPSServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "through-socks5")
	}))
	proxy := newSOCKSProxy(t, "socks-user", "socks-pass")

	transport, err := impersonate.New(
		impersonate.Chrome(),
		impersonate.WithProxy(proxy.url()),
		impersonate.WithRootCAs(pool),
	)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(transport.CloseIdleConnections)

	client := &http.Client{Transport: transport}
	resp, err := client.Get(target.URL)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if string(body) != "through-socks5" {
		t.Fatalf("body = %q", body)
	}
	if resp.ProtoMajor != 2 {
		t.Fatalf("proto = %s", resp.Proto)
	}
	if proxy.targetCount() != 1 {
		t.Fatalf("SOCKS target count = %d", proxy.targetCount())
	}
}

func TestProxyInvalidURL(t *testing.T) {
	tests := []string{
		"",
		"proxy.example.com:8080",
		"ftp://proxy.example.com:21",
		"http://",
		"http://:8080",
		"http://proxy.example.com:notaport",
		"http://proxy.example.com:0",
		"http://proxy.example.com:65536",
		"http://proxy.example.com:",
		"http://proxy.example.com:8080/path",
		"http://proxy.example.com:8080?x=1",
		"socks5://proxy.example.com",
	}
	for _, raw := range tests {
		t.Run(raw, func(t *testing.T) {
			_, err := impersonate.New(impersonate.Chrome(), impersonate.WithProxy(raw))
			if err == nil || !strings.Contains(err.Error(), "configuration error") {
				t.Fatalf("New err = %v", err)
			}
		})
	}
}

func TestProxyCredentialsNotInError(t *testing.T) {
	_, err := impersonate.New(
		impersonate.Chrome(),
		impersonate.WithProxy("http://user:super-secret@proxy.example.com:notaport"),
	)
	if err == nil {
		t.Fatal("expected error")
	}
	if strings.Contains(err.Error(), "super-secret") {
		t.Fatalf("error leaked credentials: %v", err)
	}
}
