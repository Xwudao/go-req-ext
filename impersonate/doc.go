package impersonate

// Package impersonate provides a standard-library-compatible http.RoundTripper
// that simulates browser TLS ClientHello and HTTP/2 fingerprints.
//
// The package is intentionally a separate module from go-req and from the
// lightweight go-req-ext packages (jar, persist). Importing those packages
// does not download, compile, or link this module or its uTLS/fhttp/browser
// profile dependencies. This package returns a plain http.RoundTripper and
// does not require changes to go-req or net/http:
//
//	transport, err := impersonate.New(impersonate.Chrome())
//	if err != nil {
//		return err
//	}
//	client := req.New(req.WithTransport(transport))
//
// Profiles are concrete snapshots of upstream fingerprint data, not claims
// about every version of a browser. Fingerprint simulation is also not a full
// browser environment and does not guarantee bypassing any site's detection.
// See the module README for supported protocols, proxy boundaries, and
// lifecycle details.
