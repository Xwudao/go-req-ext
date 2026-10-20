package impersonate

import (
	"crypto/x509"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const (
	defaultIdleConnTimeout  = 90 * time.Second
	defaultHandshakeTimeout = 15 * time.Second
)

type config struct {
	proxy              *url.URL
	rootCAs            *x509.CertPool
	insecureSkipVerify bool
	headerOrder        []string
	hasHeaderOrder     bool
	idleConnTimeout    time.Duration
	handshakeTimeout   time.Duration
}

func defaultConfig() config {
	return config{
		idleConnTimeout:  defaultIdleConnTimeout,
		handshakeTimeout: defaultHandshakeTimeout,
	}
}

// Option configures a Transport.
type Option func(*config) error

// WithProxy configures an explicit proxy. Supported schemes are http, https,
// socks5, and socks5h. HTTP and HTTPS proxies are used through CONNECT,
// including for plain HTTP destinations; the proxy must permit CONNECT to the
// destination port.
//
// HTTP and HTTPS proxy URLs may omit the port to use 80 or 443. SOCKS5 proxy
// URLs must include a port. Username and password information is supported and
// is never included in Debug output.
func WithProxy(rawURL string) Option {
	return func(cfg *config) error {
		u, err := parseProxyURL(rawURL)
		if err != nil {
			return err
		}
		cfg.proxy = u
		return nil
	}
}

// WithRootCAs sets the certificate roots used to verify HTTPS targets and
// HTTPS proxies.
func WithRootCAs(pool *x509.CertPool) Option {
	return func(cfg *config) error {
		if pool == nil {
			return configError("root CA pool must not be nil")
		}
		cfg.rootCAs = pool.Clone()
		return nil
	}
}

// WithInsecureSkipVerify disables certificate verification for HTTPS targets
// and HTTPS proxies. It is intended for controlled tests only.
func WithInsecureSkipVerify() Option {
	return func(cfg *config) error {
		cfg.insecureSkipVerify = true
		return nil
	}
}

// WithHeaderOrder overrides the profile's default request header order.
// Header names are lowercased. Passing no names disables automatic header
// ordering while still allowing a request-level Header-Order setting.
func WithHeaderOrder(order ...string) Option {
	return func(cfg *config) error {
		cfg.hasHeaderOrder = true
		cfg.headerOrder = normalizeHeaderOrder(order)
		return nil
	}
}

// WithIdleConnTimeout sets the idle connection timeout used by the HTTP/1 and
// HTTP/2 transports. Zero means no timeout.
func WithIdleConnTimeout(timeout time.Duration) Option {
	return func(cfg *config) error {
		if timeout < 0 {
			return configError("idle connection timeout must not be negative")
		}
		cfg.idleConnTimeout = timeout
		return nil
	}
}

// WithHandshakeTimeout sets the timeout for TLS handshakes initiated without a
// request context, currently new HTTP/2 connections. Initial protocol probing
// always uses the request context.
func WithHandshakeTimeout(timeout time.Duration) Option {
	return func(cfg *config) error {
		if timeout < 0 {
			return configError("handshake timeout must not be negative")
		}
		cfg.handshakeTimeout = timeout
		return nil
	}
}

func parseProxyURL(raw string) (*url.URL, error) {
	if strings.TrimSpace(raw) == "" {
		return nil, configError("proxy URL must not be empty")
	}

	u, err := url.Parse(raw)
	if err != nil {
		// Do not include the original error text: url.Error may contain the
		// full URL, including credentials.
		return nil, configError("invalid proxy URL")
	}

	scheme := strings.ToLower(u.Scheme)
	switch scheme {
	case "http", "https", "socks5", "socks5h":
	default:
		return nil, configError(
			"proxy URL scheme %q is not supported; use http, https, socks5, or socks5h",
			u.Scheme,
		)
	}

	if u.Opaque != "" || u.Host == "" || u.Hostname() == "" {
		return nil, configError("proxy URL must be absolute and include a host")
	}
	if strings.HasSuffix(u.Host, ":") {
		return nil, configError("proxy URL contains an empty port")
	}
	if u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.RawFragment != "" {
		return nil, configError("proxy URL must not contain a query or fragment")
	}
	if u.Path != "" && u.Path != "/" {
		return nil, configError("proxy URL must not contain a path")
	}

	port := u.Port()
	if port != "" {
		n, err := strconv.Atoi(port)
		if err != nil || n < 1 || n > 65535 {
			return nil, configError("proxy URL port %q must be between 1 and 65535", port)
		}
	} else if scheme == "socks5" || scheme == "socks5h" {
		return nil, configError("proxy URL with scheme %q must include a port", scheme)
	} else if scheme == "http" {
		u.Host = net.JoinHostPort(u.Hostname(), "80")
	} else if scheme == "https" {
		u.Host = net.JoinHostPort(u.Hostname(), "443")
	}

	clone := *u
	return &clone, nil
}

func normalizeHeaderOrder(order []string) []string {
	if len(order) == 0 {
		return nil
	}
	out := make([]string, 0, len(order))
	for _, name := range order {
		name = strings.ToLower(strings.TrimSpace(name))
		if name != "" {
			out = append(out, name)
		}
	}
	return out
}
