package impersonate_test

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
	"time"

	"github.com/Xwudao/go-req-ext/impersonate"
	fhttp2 "github.com/bogdanfinn/fhttp/http2"
	"github.com/bogdanfinn/tls-client/profiles"
	"golang.org/x/net/http2/hpack"
)

const http2ClientPreface = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"

type h2Setting struct {
	id    fhttp2.SettingID
	value uint32
}

type h2Capture struct {
	settings       []h2Setting
	connectionFlow uint32
	headerNames    []string
	err            error
}

func TestHTTP2FingerprintMatchesProfile(t *testing.T) {
	addr, pool, captured := startH2CaptureServer(t)
	transport, err := impersonate.New(impersonate.Chrome(), impersonate.WithRootCAs(pool))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(transport.CloseIdleConnections)

	client := &http.Client{Transport: transport}
	req, _ := http.NewRequest(http.MethodGet, "https://"+addr+"/fingerprint", nil)
	req.Header.Set("Accept", "*/*")
	req.Header.Set("User-Agent", "impersonate-test")
	req.Header.Set("Accept-Language", "en-US,en;q=0.9")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if string(body) != "ok" {
		t.Fatalf("body = %q", body)
	}

	var cap h2Capture
	select {
	case cap = <-captured:
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for HTTP/2 capture")
	}
	if cap.err != nil {
		t.Fatalf("capture server: %v", cap.err)
	}

	profile := profiles.MappedTLSClients["chrome_150"]
	wantOrder := profile.GetSettingsOrder()
	gotOrder := make([]fhttp2.SettingID, len(cap.settings))
	for i, setting := range cap.settings {
		gotOrder[i] = setting.id
	}
	if !reflect.DeepEqual(gotOrder, wantOrder) {
		t.Fatalf("SETTINGS order\n got: %v\nwant: %v", gotOrder, wantOrder)
	}
	wantSettings := profile.GetSettings()
	for _, setting := range cap.settings {
		if got, want := setting.value, wantSettings[setting.id]; got != want {
			t.Fatalf("SETTINGS[%v] = %d, want %d", setting.id, got, want)
		}
	}
	if got, want := cap.connectionFlow, profile.GetConnectionFlow(); got != want {
		t.Fatalf("connection WINDOW_UPDATE = %d, want %d", got, want)
	}
	if len(cap.headerNames) < 4 {
		t.Fatalf("decoded only %d header fields", len(cap.headerNames))
	}
	if got, want := cap.headerNames[:4], profile.GetPseudoHeaderOrder(); !reflect.DeepEqual(got, want) {
		t.Fatalf("pseudo-header order\n got: %v\nwant: %v", got, want)
	}
	wantRegular := []string{"user-agent", "accept", "accept-encoding", "accept-language"}
	if got := cap.headerNames[4:]; !reflect.DeepEqual(got, wantRegular) {
		t.Fatalf("regular header order\n got: %v\nwant: %v", got, wantRegular)
	}
}

func startH2CaptureServer(t *testing.T) (string, *x509.CertPool, <-chan h2Capture) {
	t.Helper()

	certServer := httptest.NewTLSServer(http.NotFoundHandler())
	cert := certServer.TLS.Certificates[0]
	pool := x509.NewCertPool()
	pool.AddCert(certServer.Certificate())
	certServer.Close()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = listener.Close() })

	captured := make(chan h2Capture, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			captured <- h2Capture{err: err}
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(10 * time.Second))

		tlsConn := tls.Server(conn, &tls.Config{
			Certificates: []tls.Certificate{cert},
			NextProtos:   []string{"h2"},
		})
		if err := tlsConn.Handshake(); err != nil {
			captured <- h2Capture{err: fmt.Errorf("TLS handshake: %w", err)}
			return
		}
		if got := tlsConn.ConnectionState().NegotiatedProtocol; got != "h2" {
			captured <- h2Capture{err: fmt.Errorf("ALPN = %q", got)}
			return
		}

		reader := bufio.NewReader(tlsConn)
		preface := make([]byte, len(http2ClientPreface))
		if _, err := io.ReadFull(reader, preface); err != nil {
			captured <- h2Capture{err: fmt.Errorf("read preface: %w", err)}
			return
		}
		if string(preface) != http2ClientPreface {
			captured <- h2Capture{err: fmt.Errorf("bad preface %q", preface)}
			return
		}

		if err := writeH2Frame(tlsConn, 0x4, 0, 0, nil); err != nil {
			captured <- h2Capture{err: err}
			return
		}

		cap, err := readH2Fingerprint(reader, tlsConn)
		captured <- h2Capture{settings: cap.settings, connectionFlow: cap.connectionFlow, headerNames: cap.headerNames, err: err}
	}()

	return listener.Addr().String(), pool, captured
}

func readH2Fingerprint(reader *bufio.Reader, writer net.Conn) (h2Capture, error) {
	var capture h2Capture
	var headerBlock bytes.Buffer
	inHeaders := false

	for {
		header := make([]byte, 9)
		if _, err := io.ReadFull(reader, header); err != nil {
			return capture, err
		}
		length := int(header[0])<<16 | int(header[1])<<8 | int(header[2])
		frameType := header[3]
		flags := header[4]
		streamID := binary.BigEndian.Uint32(header[5:9]) & 0x7fffffff
		payload := make([]byte, length)
		if _, err := io.ReadFull(reader, payload); err != nil {
			return capture, err
		}

		switch frameType {
		case 0x4: // SETTINGS
			if flags&0x1 != 0 {
				continue
			}
			for len(payload) >= 6 {
				capture.settings = append(capture.settings, h2Setting{
					id:    fhttp2.SettingID(binary.BigEndian.Uint16(payload[0:2])),
					value: binary.BigEndian.Uint32(payload[2:6]),
				})
				payload = payload[6:]
			}
			if err := writeH2Frame(writer, 0x4, 0x1, 0, nil); err != nil {
				return capture, err
			}
		case 0x8: // WINDOW_UPDATE
			if streamID == 0 && len(payload) == 4 {
				capture.connectionFlow = binary.BigEndian.Uint32(payload) & 0x7fffffff
			}
		case 0x1: // HEADERS
			if streamID != 1 {
				continue
			}
			if flags&0x20 != 0 && len(payload) >= 5 {
				payload = payload[5:]
			}
			headerBlock.Write(payload)
			inHeaders = true
			if flags&0x4 == 0 {
				continue
			}
		case 0x9: // CONTINUATION
			if !inHeaders || streamID != 1 {
				continue
			}
			headerBlock.Write(payload)
			if flags&0x4 == 0 {
				continue
			}
		default:
			continue
		}

		if (frameType == 0x1 || frameType == 0x9) && inHeaders {
			decoder := hpack.NewDecoder(4096, nil)
			fields, err := decoder.DecodeFull(headerBlock.Bytes())
			if err != nil {
				return capture, fmt.Errorf("decode HPACK: %w", err)
			}
			for _, field := range fields {
				capture.headerNames = append(capture.headerNames, field.Name)
			}
			if err := writeH2Response(writer); err != nil {
				return capture, err
			}
			return capture, nil
		}
	}
}

func writeH2Response(writer net.Conn) error {
	var block bytes.Buffer
	encoder := hpack.NewEncoder(&block)
	for _, field := range []hpack.HeaderField{
		{Name: ":status", Value: "200"},
		{Name: "content-type", Value: "text/plain"},
		{Name: "content-length", Value: "2"},
	} {
		if err := encoder.WriteField(field); err != nil {
			return err
		}
	}
	if err := writeH2Frame(writer, 0x1, 0x4, 1, block.Bytes()); err != nil {
		return err
	}
	return writeH2Frame(writer, 0x0, 0x1, 1, []byte("ok"))
}

func writeH2Frame(writer io.Writer, frameType, flags byte, streamID uint32, payload []byte) error {
	header := make([]byte, 9)
	header[0] = byte(len(payload) >> 16)
	header[1] = byte(len(payload) >> 8)
	header[2] = byte(len(payload))
	header[3] = frameType
	header[4] = flags
	binary.BigEndian.PutUint32(header[5:], streamID)
	if _, err := writer.Write(header); err != nil {
		return err
	}
	_, err := writer.Write(payload)
	return err
}
