package impersonate

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	xproxy "golang.org/x/net/proxy"
)

type proxyDialer struct {
	url      *url.URL
	direct   net.Dialer
	rootCAs  *x509.CertPool
	insecure bool
}

func newProxyDialer(u *url.URL, rootCAs *x509.CertPool, insecure bool) *proxyDialer {
	return &proxyDialer{
		url:      u,
		rootCAs:  rootCAs,
		insecure: insecure,
	}
}

func (d *proxyDialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	if d.url == nil {
		return d.direct.DialContext(ctx, network, addr)
	}

	switch strings.ToLower(d.url.Scheme) {
	case "http", "https":
		return d.dialHTTPProxy(ctx, addr)
	case "socks5", "socks5h":
		return d.dialSOCKS5(ctx, network, addr)
	default:
		return nil, configError("unsupported proxy scheme %q", d.url.Scheme)
	}
}

func (d *proxyDialer) dialHTTPProxy(ctx context.Context, target string) (net.Conn, error) {
	conn, err := d.direct.DialContext(ctx, "tcp", d.url.Host)
	if err != nil {
		return nil, err
	}
	ok := false
	defer func() {
		if !ok {
			_ = conn.Close()
		}
	}()

	if deadline, okDeadline := ctx.Deadline(); okDeadline {
		_ = conn.SetDeadline(deadline)
	}
	stopCancel := closeOnCancel(ctx, conn)
	defer stopCancel()

	if strings.EqualFold(d.url.Scheme, "https") {
		tlsConn := tls.Client(conn, &tls.Config{
			ServerName:         d.url.Hostname(),
			RootCAs:            d.rootCAs,
			InsecureSkipVerify: d.insecure,
		})
		if err := tlsConn.HandshakeContext(ctx); err != nil {
			return nil, err
		}
		conn = tlsConn
	}

	auth := ""
	if d.url.User != nil && d.url.User.Username() != "" {
		password, _ := d.url.User.Password()
		auth = "Basic " + base64.StdEncoding.EncodeToString(
			[]byte(d.url.User.Username()+":"+password),
		)
	}

	var request strings.Builder
	fmt.Fprintf(&request, "CONNECT %s HTTP/1.1\r\n", target)
	fmt.Fprintf(&request, "Host: %s\r\n", target)
	request.WriteString("Proxy-Connection: Keep-Alive\r\n")
	if auth != "" {
		fmt.Fprintf(&request, "Proxy-Authorization: %s\r\n", auth)
	}
	request.WriteString("\r\n")

	if _, err := io.WriteString(conn, request.String()); err != nil {
		return nil, err
	}

	reader := bufio.NewReader(conn)
	statusLine, err := readProxyLine(reader)
	if err != nil {
		return nil, err
	}
	fields := strings.Fields(statusLine)
	if len(fields) < 2 {
		return nil, fmt.Errorf("impersonate: malformed proxy CONNECT response")
	}
	status, err := strconv.Atoi(fields[1])
	if err != nil {
		return nil, fmt.Errorf("impersonate: malformed proxy CONNECT status %q", fields[1])
	}
	for {
		line, err := readProxyLine(reader)
		if err != nil {
			return nil, err
		}
		if line == "" {
			break
		}
	}
	if status != 200 {
		return nil, fmt.Errorf("impersonate: proxy CONNECT failed with status %d", status)
	}

	_ = conn.SetDeadline(time.Time{})
	ok = true
	if reader.Buffered() > 0 {
		return &bufferedConn{Conn: conn, reader: reader}, nil
	}
	return conn, nil
}

func (d *proxyDialer) dialSOCKS5(ctx context.Context, network, target string) (net.Conn, error) {
	forward := &contextForwardDialer{
		ctx:    ctx,
		dialer: &d.direct,
		done:   make(chan struct{}),
	}
	defer forward.finish()

	var auth *xproxy.Auth
	if d.url.User != nil && d.url.User.Username() != "" {
		password, _ := d.url.User.Password()
		auth = &xproxy.Auth{
			User:     d.url.User.Username(),
			Password: password,
		}
	}
	dialer, err := xproxy.SOCKS5("tcp", d.url.Host, auth, forward)
	if err != nil {
		return nil, err
	}
	return dialer.Dial(network, target)
}

type contextForwardDialer struct {
	ctx    context.Context
	dialer *net.Dialer
	done   chan struct{}
	once   sync.Once
}

func (d *contextForwardDialer) Dial(network, address string) (net.Conn, error) {
	conn, err := d.dialer.DialContext(d.ctx, network, address)
	if err != nil {
		return nil, err
	}
	if d.ctx.Done() != nil {
		go func() {
			select {
			case <-d.ctx.Done():
				_ = conn.Close()
			case <-d.done:
			}
		}()
	}
	return conn, nil
}

func (d *contextForwardDialer) finish() {
	d.once.Do(func() { close(d.done) })
}

func closeOnCancel(ctx context.Context, conn net.Conn) func() {
	if ctx.Done() == nil {
		return func() {}
	}
	done := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			_ = conn.Close()
		case <-done:
		}
	}()
	return func() { close(done) }
}

func readProxyLine(reader *bufio.Reader) (string, error) {
	line, err := reader.ReadString('\n')
	if err != nil {
		return "", err
	}
	if len(line) > 32<<10 {
		return "", fmt.Errorf("impersonate: proxy response line too large")
	}
	return strings.TrimRight(line, "\r\n"), nil
}

type bufferedConn struct {
	net.Conn
	reader *bufio.Reader
}

func (c *bufferedConn) Read(p []byte) (int, error) {
	return c.reader.Read(p)
}
