package impersonate

import (
	"context"
	"crypto/x509"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	fhttp "github.com/bogdanfinn/fhttp"
	fhttp2 "github.com/bogdanfinn/fhttp/http2"
	utls "github.com/bogdanfinn/utls"
)

const (
	defaultMaxIdleConns        = 100
	defaultMaxIdleConnsPerHost = 10
)

// Transport is a standard-library http.RoundTripper that performs browser-like
// TLS ClientHello and HTTP/2 negotiation using a concrete Profile.
//
// It intentionally implements only http.RoundTripper plus
// CloseIdleConnections. The same Transport can be passed to req.WithTransport
// or to a standard http.Client.Transports. It is safe for concurrent use.
type Transport struct {
	profile            Profile
	headerOrder        []string
	dialer             *proxyDialer
	rootCAs            *x509.CertPool
	insecureSkipVerify bool
	idleConnTimeout    time.Duration
	handshakeTimeout   time.Duration
	sessionCache       utls.ClientSessionCache

	mu         sync.Mutex
	transports map[string]fhttp.RoundTripper
	pending    map[string]net.Conn
}

// New creates an impersonating Transport for profile.
//
// New performs no network I/O. The first request probes the target's ALPN and
// creates either an HTTP/1 or HTTP/2 transport configured from the profile.
func New(profile Profile, opts ...Option) (*Transport, error) {
	if err := profile.validate(); err != nil {
		return nil, err
	}

	cfg := defaultConfig()
	for _, opt := range opts {
		if opt == nil {
			return nil, configError("nil option")
		}
		if err := opt(&cfg); err != nil {
			return nil, err
		}
	}

	headerOrder := profile.HeaderOrder()
	if cfg.hasHeaderOrder {
		headerOrder = append([]string(nil), cfg.headerOrder...)
	}

	return &Transport{
		profile:            profile,
		headerOrder:        headerOrder,
		dialer:             newProxyDialer(cfg.proxy, cfg.rootCAs, cfg.insecureSkipVerify),
		rootCAs:            cfg.rootCAs,
		insecureSkipVerify: cfg.insecureSkipVerify,
		idleConnTimeout:    cfg.idleConnTimeout,
		handshakeTimeout:   cfg.handshakeTimeout,
		sessionCache:       utls.NewLRUClientSessionCache(32),
		transports:         make(map[string]fhttp.RoundTripper),
		pending:            make(map[string]net.Conn),
	}, nil
}

// Profile returns the profile used by the Transport.
func (t *Transport) Profile() Profile {
	if t == nil {
		return Profile{}
	}
	return t.profile
}

// RoundTrip implements http.RoundTripper.
//
// Request and response bodies are never fully buffered by the adapter. Request
// context cancellation, deadlines, response streaming, and Body.Close are
// preserved by the underlying fhttp transport and a thin body wrapper.
func (t *Transport) RoundTrip(req *http.Request) (*http.Response, error) {
	if t == nil {
		return nil, configError("nil Transport")
	}
	if req == nil {
		return nil, configError("nil HTTP request")
	}
	if req.URL == nil {
		return nil, configError("HTTP request has no URL")
	}

	scheme := strings.ToLower(req.URL.Scheme)
	if scheme != "http" && scheme != "https" {
		return nil, configError("unsupported URL scheme %q", req.URL.Scheme)
	}

	freq, err := toFHTTPRequest(req, t.headerOrder)
	if err != nil {
		closeRequestBody(req)
		return nil, err
	}

	addr := canonicalAddr(req.URL, scheme)
	rt, err := t.transportFor(req.Context(), scheme, addr)
	if err != nil {
		closeRequestBody(req)
		return nil, err
	}

	fresp, err := rt.RoundTrip(freq)
	if err != nil {
		return nil, err
	}
	return fromFHTTPResponse(fresp, req), nil
}

// CloseIdleConnections closes idle connections held by all cached HTTP/1 and
// HTTP/2 transports. Active requests are unaffected. The Transport remains
// usable after this call.
func (t *Transport) CloseIdleConnections() {
	if t == nil {
		return
	}

	t.mu.Lock()
	transports := make([]fhttp.RoundTripper, 0, len(t.transports))
	for _, rt := range t.transports {
		transports = append(transports, rt)
	}
	pending := t.pending
	t.pending = make(map[string]net.Conn)
	t.mu.Unlock()

	for _, conn := range pending {
		_ = conn.Close()
	}
	for _, rt := range transports {
		if closer, ok := rt.(interface{ CloseIdleConnections() }); ok {
			closer.CloseIdleConnections()
		}
	}
}

func (t *Transport) transportFor(ctx context.Context, scheme, addr string) (fhttp.RoundTripper, error) {
	key := scheme + "|" + addr

	t.mu.Lock()
	rt := t.transports[key]
	t.mu.Unlock()
	if rt != nil {
		return rt, nil
	}

	if scheme == "http" {
		rt = t.newHTTP1Transport(false)
		return t.installTransport(key, rt), nil
	}

	// Probe ALPN once per address, then hand the already-negotiated connection
	// to the selected transport. This avoids forcing every request through a
	// protocol-detect-and-upgrade path.
	conn, state, err := t.dialTLS(ctx, addr)
	if err != nil {
		return nil, err
	}

	t.mu.Lock()
	if existing := t.transports[key]; existing != nil {
		t.mu.Unlock()
		_ = conn.Close()
		return existing, nil
	}
	t.pending[addr] = conn
	if state.NegotiatedProtocol == fhttp2.NextProtoTLS {
		rt = t.newHTTP2Transport()
	} else {
		rt = t.newHTTP1Transport(true)
	}
	t.transports[key] = rt
	t.mu.Unlock()
	return rt, nil
}

func (t *Transport) installTransport(key string, rt fhttp.RoundTripper) fhttp.RoundTripper {
	t.mu.Lock()
	defer t.mu.Unlock()
	if existing := t.transports[key]; existing != nil {
		return existing
	}
	t.transports[key] = rt
	return rt
}

func (t *Transport) takePending(addr string) net.Conn {
	t.mu.Lock()
	defer t.mu.Unlock()
	conn := t.pending[addr]
	delete(t.pending, addr)
	return conn
}

func (t *Transport) newHTTP1Transport(tlsMode bool) *fhttp.Transport {
	transport := &fhttp.Transport{
		Proxy:               nil,
		DialContext:         t.dialer.DialContext,
		MaxIdleConns:        defaultMaxIdleConns,
		MaxIdleConnsPerHost: defaultMaxIdleConnsPerHost,
		IdleConnTimeout:     t.idleConnTimeout,
		ForceAttemptHTTP2:   false,
		// A non-nil empty map disables fhttp's automatic HTTP/2 upgrade. The
		// profile-aware HTTP/2 transport is selected explicitly above.
		TLSNextProto: map[string]func(string, *utls.Conn) fhttp.RoundTripper{},
	}
	if tlsMode {
		transport.TLSClientConfig = t.newTLSConfig("")
		transport.TLSHandshakeTimeout = t.handshakeTimeout
		transport.DialTLSContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
			if conn := t.takePending(addr); conn != nil {
				return conn, nil
			}
			conn, _, err := t.dialTLS(ctx, addr)
			return conn, err
		}
	}
	return transport
}

func (t *Transport) newHTTP2Transport() *fhttp2.Transport {
	settings := cloneSettings(t.profile.clientProfile.GetSettings())
	settingsOrder := append([]fhttp2.SettingID(nil), t.profile.clientProfile.GetSettingsOrder()...)
	priorities := append([]fhttp2.Priority(nil), t.profile.clientProfile.GetPriorities()...)
	pseudoHeaderOrder := append([]string(nil), t.profile.clientProfile.GetPseudoHeaderOrder()...)

	return &fhttp2.Transport{
		DialTLS: func(network, addr string, _ *utls.Config) (net.Conn, error) {
			if conn := t.takePending(addr); conn != nil {
				return conn, nil
			}
			ctx := context.Background()
			cancel := func() {}
			if t.handshakeTimeout > 0 {
				ctx, cancel = context.WithTimeout(ctx, t.handshakeTimeout)
			}
			defer cancel()
			conn, _, err := t.dialTLS(ctx, addr)
			return conn, err
		},
		TLSClientConfig:   t.newTLSConfig(""),
		ConnectionFlow:    t.profile.clientProfile.GetConnectionFlow(),
		Settings:          settings,
		SettingsOrder:     settingsOrder,
		Priorities:        priorities,
		HeaderPriority:    t.profile.clientProfile.GetHeaderPriority(),
		PseudoHeaderOrder: pseudoHeaderOrder,
		InitialStreamID:   t.profile.clientProfile.GetStreamID(),
		AllowHTTP:         t.profile.clientProfile.GetAllowHTTP(),
		IdleConnTimeout:   t.idleConnTimeout,
		PushHandler:       &fhttp2.DefaultPushHandler{},
	}
}

func canonicalAddr(u *url.URL, scheme string) string {
	host := u.Host
	if u.Port() == "" {
		port := "80"
		if scheme == "https" {
			port = "443"
		}
		host = net.JoinHostPort(u.Hostname(), port)
	}
	return host
}

func cloneSettings(settings map[fhttp2.SettingID]uint32) map[fhttp2.SettingID]uint32 {
	if settings == nil {
		return nil
	}
	copy := make(map[fhttp2.SettingID]uint32, len(settings))
	for key, value := range settings {
		copy[key] = value
	}
	return copy
}

func closeRequestBody(req *http.Request) {
	if req.Body != nil && req.Body != http.NoBody {
		_ = req.Body.Close()
	}
}

func (t *Transport) String() string {
	if t == nil {
		return "<nil>"
	}
	return fmt.Sprintf("impersonate.Transport(%s)", t.profile.describe())
}
