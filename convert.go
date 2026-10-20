package impersonate

import (
	stdtls "crypto/tls"
	"io"
	"net/http"
	"strings"
	"sync"

	fhttp "github.com/bogdanfinn/fhttp"
	utls "github.com/bogdanfinn/utls"
)

func toFHTTPRequest(req *http.Request, headerOrder []string) (*fhttp.Request, error) {
	if req.URL == nil {
		return nil, configError("HTTP request has no URL")
	}

	header := toFHTTPHeader(req.Header)
	if len(headerOrder) > 0 && !hasFHTTPHeaderOrder(header) {
		header[fhttp.HeaderOrderKey] = append([]string(nil), headerOrder...)
	}

	freq := &fhttp.Request{
		Method:           req.Method,
		URL:              req.URL,
		Header:           header,
		Body:             req.Body,
		GetBody:          req.GetBody,
		ContentLength:    req.ContentLength,
		TransferEncoding: append([]string(nil), req.TransferEncoding...),
		Close:            req.Close,
		Host:             req.Host,
		Trailer:          toFHTTPHeader(req.Trailer),
	}
	return freq.WithContext(req.Context()), nil
}

func toFHTTPHeader(src http.Header) fhttp.Header {
	if src == nil {
		return nil
	}
	dst := make(fhttp.Header, len(src))
	for key, values := range src {
		switch {
		case strings.EqualFold(key, fhttp.HeaderOrderKey):
			key = fhttp.HeaderOrderKey
			values = normalizeHeaderOrder(values)
		case strings.EqualFold(key, fhttp.PHeaderOrderKey):
			key = fhttp.PHeaderOrderKey
			values = normalizeHeaderOrder(values)
		}
		dst[key] = append([]string(nil), values...)
	}
	return dst
}

func hasFHTTPHeaderOrder(header fhttp.Header) bool {
	for key := range header {
		if strings.EqualFold(key, fhttp.HeaderOrderKey) {
			return true
		}
	}
	return false
}

func fromFHTTPResponse(resp *fhttp.Response, original *http.Request) *http.Response {
	if resp == nil {
		return nil
	}

	out := &http.Response{
		Status:           resp.Status,
		StatusCode:       resp.StatusCode,
		Proto:            resp.Proto,
		ProtoMajor:       resp.ProtoMajor,
		ProtoMinor:       resp.ProtoMinor,
		Header:           fromFHTTPHeader(resp.Header),
		ContentLength:    resp.ContentLength,
		TransferEncoding: append([]string(nil), resp.TransferEncoding...),
		Close:            resp.Close,
		Uncompressed:     resp.Uncompressed,
		Trailer:          fromFHTTPHeader(resp.Trailer),
		Request:          original,
		TLS:              fromUTLSConnectionState(resp.TLS),
	}

	if resp.Body == nil {
		out.Body = http.NoBody
		return out
	}

	updateTrailer := func() {
		if resp.Trailer == nil {
			return
		}
		if out.Trailer == nil {
			out.Trailer = make(http.Header, len(resp.Trailer))
		}
		for key, values := range resp.Trailer {
			out.Trailer[http.CanonicalHeaderKey(key)] = append([]string(nil), values...)
		}
	}
	out.Body = &trailerBody{
		ReadCloser: resp.Body,
		update:     updateTrailer,
	}
	return out
}

func fromFHTTPHeader(src fhttp.Header) http.Header {
	if src == nil {
		return nil
	}
	dst := make(http.Header, len(src))
	for key, values := range src {
		if strings.EqualFold(key, fhttp.HeaderOrderKey) || strings.EqualFold(key, fhttp.PHeaderOrderKey) {
			continue
		}
		dst[http.CanonicalHeaderKey(key)] = append([]string(nil), values...)
	}
	return dst
}

type trailerBody struct {
	io.ReadCloser
	once   sync.Once
	update func()
}

func (b *trailerBody) Read(p []byte) (int, error) {
	n, err := b.ReadCloser.Read(p)
	if err == io.EOF {
		b.once.Do(b.update)
	}
	return n, err
}

func (b *trailerBody) Close() error {
	err := b.ReadCloser.Close()
	b.once.Do(b.update)
	return err
}

func fromUTLSConnectionState(state *utls.ConnectionState) *stdtls.ConnectionState {
	if state == nil {
		return nil
	}
	return &stdtls.ConnectionState{
		Version:                     state.Version,
		HandshakeComplete:           state.HandshakeComplete,
		DidResume:                   state.DidResume,
		CipherSuite:                 state.CipherSuite,
		NegotiatedProtocol:          state.NegotiatedProtocol,
		NegotiatedProtocolIsMutual:  state.NegotiatedProtocolIsMutual,
		ServerName:                  state.ServerName,
		PeerCertificates:            state.PeerCertificates,
		VerifiedChains:              state.VerifiedChains,
		SignedCertificateTimestamps: state.SignedCertificateTimestamps,
		OCSPResponse:                state.OCSPResponse,
		TLSUnique:                   state.TLSUnique,
		ECHAccepted:                 state.ECHAccepted,
	}
}
