package impersonate_test

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"reflect"
	"testing"
	"time"

	"github.com/Xwudao/go-req-ext/impersonate"
	"github.com/bogdanfinn/tls-client/profiles"
	utls "github.com/bogdanfinn/utls"
)

func captureClientHello(t *testing.T) (string, <-chan []byte) {
	t.Helper()
	listener, err := net.Listen("tcp", "localhost:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	hello := make(chan []byte, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		header := make([]byte, 5)
		if _, err := io.ReadFull(conn, header); err != nil {
			return
		}
		length := int(binary.BigEndian.Uint16(header[3:5]))
		payload := make([]byte, length)
		if _, err := io.ReadFull(conn, payload); err != nil {
			return
		}
		hello <- append(append([]byte(nil), header...), payload...)
	}()
	port := listener.Addr().(*net.TCPAddr).Port
	return fmt.Sprintf("localhost:%d", port), hello
}

func TestTLSClientHelloMatchesProfile(t *testing.T) {
	tests := []struct {
		name    string
		profile impersonate.Profile
		key     string
	}{
		{name: "chrome", profile: impersonate.Chrome(), key: "chrome_150"},
		{name: "firefox", profile: impersonate.Firefox(), key: "firefox_147"},
		{name: "safari", profile: impersonate.Safari(), key: "safari_16_0"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			addr, hello := captureClientHello(t)
			transport, err := impersonate.New(tc.profile)
			if err != nil {
				t.Fatalf("New: %v", err)
			}
			t.Cleanup(transport.CloseIdleConnections)

			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+addr, nil)
			_, _ = transport.RoundTrip(req)

			var raw []byte
			select {
			case raw = <-hello:
			case <-ctx.Done():
				t.Fatal("timed out waiting for ClientHello")
			}

			clientProfile := profiles.MappedTLSClients[tc.key]
			expected, err := clientProfile.GetClientHelloSpec()
			if err != nil {
				expected, err = utls.UTLSIdToSpec(clientProfile.GetClientHelloId())
				if err != nil {
					t.Fatalf("UTLSIdToSpec: %v", err)
				}
			}
			fingerprinter := &utls.Fingerprinter{AllowBluntMimicry: true}
			captured, err := fingerprinter.RawClientHello(raw)
			if err != nil {
				t.Fatalf("RawClientHello: %v", err)
			}

			if got, want := normalizeIDs(captured.CipherSuites), normalizeIDs(expected.CipherSuites); !reflect.DeepEqual(got, want) {
				t.Fatalf("cipher suites\n got: %v\nwant: %v", got, want)
			}
			if got, want := extensionTypes(captured.Extensions), extensionTypes(expected.Extensions); !reflect.DeepEqual(got, want) {
				t.Fatalf("extension order\n got: %v\nwant: %v", got, want)
			}
			if got, want := captured.CompressionMethods, expected.CompressionMethods; !reflect.DeepEqual(got, want) {
				t.Fatalf("compression methods got %v want %v", got, want)
			}

			assertExtensionValue(t, captured, &expected, func(ext *utls.SupportedCurvesExtension) any {
				return normalizeCurves(ext.Curves)
			})
			assertExtensionValue(t, captured, &expected, func(ext *utls.SupportedVersionsExtension) any {
				return normalizeIDs(ext.Versions)
			})
			assertExtensionValue(t, captured, &expected, func(ext *utls.SignatureAlgorithmsExtension) any {
				return ext.SupportedSignatureAlgorithms
			})
			assertExtensionValue(t, captured, &expected, func(ext *utls.ALPNExtension) any {
				return ext.AlpnProtocols
			})
			assertExtensionValue(t, captured, &expected, func(ext *utls.SupportedPointsExtension) any {
				return ext.SupportedPoints
			})
		})
	}
}

func assertExtensionValue[T any](t *testing.T, captured, expected *utls.ClientHelloSpec, value func(T) any) {
	t.Helper()
	var got, want T
	gotOK := findExtension(captured.Extensions, &got)
	wantOK := findExtension(expected.Extensions, &want)
	if gotOK != wantOK {
		t.Fatalf("extension %T presence got %v want %v", got, gotOK, wantOK)
	}
	if !gotOK {
		return
	}
	if g, w := value(got), value(want); !reflect.DeepEqual(g, w) {
		t.Fatalf("extension %T\n got: %v\nwant: %v", got, g, w)
	}
}

func findExtension[T any](extensions []utls.TLSExtension, target *T) bool {
	for _, ext := range extensions {
		if value, ok := ext.(T); ok {
			*target = value
			return true
		}
	}
	return false
}

func extensionTypes(extensions []utls.TLSExtension) []string {
	types := make([]string, len(extensions))
	for i, ext := range extensions {
		types[i] = reflect.TypeOf(ext).String()
	}
	return types
}

func normalizeIDs[T ~uint16](ids []T) []uint16 {
	out := make([]uint16, len(ids))
	for i, id := range ids {
		if isGREASE(uint16(id)) {
			out[i] = 0x0a0a
		} else {
			out[i] = uint16(id)
		}
	}
	return out
}

func normalizeCurves(curves []utls.CurveID) []uint16 {
	out := make([]uint16, len(curves))
	for i, curve := range curves {
		if isGREASE(uint16(curve)) {
			out[i] = 0x0a0a
		} else {
			out[i] = uint16(curve)
		}
	}
	return out
}

func isGREASE(v uint16) bool {
	return v&0x0f0f == 0x0a0a && byte(v>>8) == byte(v)
}

func TestCapturedHelloHasALPN(t *testing.T) {
	addr, hello := captureClientHello(t)
	transport, err := impersonate.New(impersonate.Chrome())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(transport.CloseIdleConnections)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+addr, nil)
	_, _ = transport.RoundTrip(req)
	raw := <-hello
	spec, err := (&utls.Fingerprinter{AllowBluntMimicry: true}).RawClientHello(raw)
	if err != nil {
		t.Fatalf("RawClientHello: %v", err)
	}
	var alpn *utls.ALPNExtension
	if !findExtension(spec.Extensions, &alpn) {
		t.Fatal("ClientHello has no ALPN extension")
	}
	if fmt.Sprint(alpn.AlpnProtocols) != "[h2 http/1.1]" {
		t.Fatalf("ALPN = %v", alpn.AlpnProtocols)
	}
}
