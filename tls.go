package impersonate

import (
	"context"
	"net"

	utls "github.com/bogdanfinn/utls"
)

func (t *Transport) newTLSConfig(serverName string) *utls.Config {
	return &utls.Config{
		ServerName:         serverName,
		RootCAs:            t.rootCAs,
		InsecureSkipVerify: t.insecureSkipVerify,
		ClientSessionCache: t.sessionCache,
		OmitEmptyPsk:       true,
	}
}

// dialTLS establishes a proxy tunnel when configured, performs a uTLS
// handshake using the selected profile, and returns the underlying uTLS
// connection. Returning *utls.Conn (rather than *utls.UConn) lets fhttp record
// TLS connection state on HTTP/1 responses.
func (t *Transport) dialTLS(ctx context.Context, addr string) (net.Conn, utls.ConnectionState, error) {
	rawConn, err := t.dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, utls.ConnectionState{}, err
	}
	ok := false
	defer func() {
		if !ok {
			_ = rawConn.Close()
		}
	}()

	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		host = addr
	}

	uconn := utls.UClient(
		rawConn,
		t.newTLSConfig(host),
		t.profile.clientProfile.GetClientHelloId(),
		false,
		false,
		false,
	)
	if err := uconn.HandshakeContext(ctx); err != nil {
		return nil, utls.ConnectionState{}, err
	}

	state := uconn.ConnectionState()
	ok = true
	return uconn.Conn, state, nil
}
