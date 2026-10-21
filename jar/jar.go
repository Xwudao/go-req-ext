// Package jar provides a concurrency-safe HTTP cookie jar with optional
// persistence.
//
// Jar implements http.CookieJar. It applies the parts of RFC 6265 that matter
// to an HTTP client: host-only and domain cookies, path matching, Secure,
// expiry, Max-Age, and HttpOnly/SameSite metadata. Expired cookies are removed
// lazily on read.
//
// The package depends only on the standard library plus the lightweight
// go-req-ext/persist package. It never imports the browser impersonation
// module, so an application that only needs cookies does not link uTLS,
// fhttp, or browser profile data into its binary.
//
// A public suffix list is optional. Pass a cookiejar.PublicSuffixList (for
// example golang.org/x/net/publicsuffix.List) to reject cookies for public
// suffixes such as "com"; without one, only syntactic domain checks apply.
package jar

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/Xwudao/go-req-ext/persist"
)

const (
	documentVersion = 1

	// maxAgeLimit avoids overflowing time.Duration for absurd Max-Age values.
	maxAgeLimit = time.Duration(1<<63 - 1)
)

// ErrConfiguration reports an invalid Jar option.
var ErrConfiguration = errors.New("jar: configuration error")

// Cookie is the serializable form of a stored cookie.
//
// Expires is zero for a session cookie. Creation and LastAccess are preserved
// across Save and Load and are used for deterministic ordering.
type Cookie struct {
	Name       string        `json:"name"`
	Value      string        `json:"value"`
	Domain     string        `json:"domain"`
	Path       string        `json:"path"`
	Expires    time.Time     `json:"expires,omitempty"`
	Secure     bool          `json:"secure,omitempty"`
	HttpOnly   bool          `json:"httpOnly,omitempty"`
	SameSite   http.SameSite `json:"sameSite,omitempty"`
	HostOnly   bool          `json:"hostOnly,omitempty"`
	Creation   time.Time     `json:"creation,omitempty"`
	LastAccess time.Time     `json:"lastAccess,omitempty"`
}

type cookieKey struct {
	domain string
	path   string
	name   string
}

type document struct {
	Version int      `json:"version"`
	Cookies []Cookie `json:"cookies"`
}

// Jar is a concurrency-safe cookie store implementing http.CookieJar.
//
// A Jar is safe for concurrent use. Its zero value is not usable; call New or
// Open.
type Jar struct {
	mu      sync.Mutex
	entries map[cookieKey]Cookie
	now     func() time.Time

	psl      cookiejar.PublicSuffixList
	store    persist.Store
	autoSave time.Duration
	timer    *time.Timer
	closed   bool
	lastErr  error
	onError  func(error)

	// saveMu serializes store access independently of mu, so slow I/O does
	// not block cookie lookups.
	saveMu sync.Mutex
}

// Option configures a Jar.
type Option func(*Jar) error

// WithStore enables persistence with store. The Jar still performs no I/O
// until Load, Save, or Close is called, unless WithAutoSave is also used.
func WithStore(store persist.Store) Option {
	return func(j *Jar) error {
		if store == nil {
			return configError("store must not be nil")
		}
		j.store = store
		return nil
	}
}

// WithAutoSave flushes cookie changes after interval of inactivity. Repeated
// changes within the interval are coalesced into one write.
//
// Auto-save requires a store. Asynchronous errors are reported through Err and,
// if configured, WithErrorHandler. Close stops auto-save and performs a final
// synchronous Save. An interval of zero disables auto-save.
func WithAutoSave(interval time.Duration) Option {
	return func(j *Jar) error {
		if interval < 0 {
			return configError("auto-save interval must not be negative")
		}
		j.autoSave = interval
		return nil
	}
}

// WithPublicSuffixList sets the public suffix policy used when accepting
// domain cookies. A nil list disables public suffix checks.
func WithPublicSuffixList(psl cookiejar.PublicSuffixList) Option {
	return func(j *Jar) error {
		j.psl = psl
		return nil
	}
}

// WithErrorHandler sets a callback for asynchronous persistence errors, such
// as failures from auto-save. The callback runs outside Jar locks.
func WithErrorHandler(fn func(error)) Option {
	return func(j *Jar) error {
		j.onError = fn
		return nil
	}
}

// New creates an empty Jar.
func New(opts ...Option) (*Jar, error) {
	j := &Jar{
		entries: make(map[cookieKey]Cookie),
		now:     time.Now,
	}
	for _, opt := range opts {
		if opt == nil {
			return nil, configError("nil option")
		}
		if err := opt(j); err != nil {
			return nil, err
		}
	}
	if j.autoSave > 0 && j.store == nil {
		return nil, configError("auto-save requires a store")
	}
	return j, nil
}

// Open creates a Jar and loads persisted cookies when a store is configured.
// A missing store value is treated as an empty jar.
func Open(ctx context.Context, opts ...Option) (*Jar, error) {
	j, err := New(opts...)
	if err != nil {
		return nil, err
	}
	if err := j.Load(ctx); err != nil {
		return nil, err
	}
	return j, nil
}

// SetCookies implements http.CookieJar. Nil cookies, invalid names, cookies
// for non-HTTP schemes, and Secure cookies received over plain HTTP are
// ignored. MaxAge < 0 and already-expired cookies delete a matching entry.
func (j *Jar) SetCookies(u *url.URL, cookies []*http.Cookie) {
	if j == nil || u == nil {
		return
	}
	scheme := strings.ToLower(u.Scheme)
	if scheme != "http" && scheme != "https" {
		return
	}
	host := canonicalHost(u.Hostname())
	if host == "" {
		return
	}

	now := j.now()

	j.mu.Lock()
	changed := false
	for _, c := range cookies {
		if c == nil {
			continue
		}
		if j.setCookieLocked(u, host, scheme, c, now) {
			changed = true
		}
	}
	if changed {
		j.afterChangeLocked()
	}
	j.mu.Unlock()
}

// Cookies implements http.CookieJar. It returns matching cookies sorted by
// descending path length and then by creation time, as required by RFC 6265.
func (j *Jar) Cookies(u *url.URL) []*http.Cookie {
	if j == nil || u == nil {
		return nil
	}
	scheme := strings.ToLower(u.Scheme)
	if scheme != "http" && scheme != "https" {
		return nil
	}
	host := canonicalHost(u.Hostname())
	if host == "" {
		return nil
	}
	requestPath := u.Path
	if requestPath == "" || requestPath[0] != '/' {
		requestPath = "/"
	}

	now := j.now()

	j.mu.Lock()
	defer j.mu.Unlock()

	matched := make([]Cookie, 0, len(j.entries))
	for key, c := range j.entries {
		if isExpired(c, now) {
			delete(j.entries, key)
			continue
		}
		if c.Secure && scheme != "https" {
			continue
		}
		if !domainMatches(host, c.Domain, c.HostOnly) {
			continue
		}
		if !pathMatches(requestPath, c.Path) {
			continue
		}
		c.LastAccess = now
		j.entries[key] = c
		matched = append(matched, c)
	}

	sort.Slice(matched, func(a, b int) bool {
		if len(matched[a].Path) != len(matched[b].Path) {
			return len(matched[a].Path) > len(matched[b].Path)
		}
		if !matched[a].Creation.Equal(matched[b].Creation) {
			return matched[a].Creation.Before(matched[b].Creation)
		}
		return matched[a].Name < matched[b].Name
	})

	out := make([]*http.Cookie, len(matched))
	for i, c := range matched {
		out[i] = &http.Cookie{Name: c.Name, Value: c.Value}
	}
	return out
}

// Snapshot returns a copy of all stored cookies, including session cookies and
// metadata. Expired cookies are removed first.
func (j *Jar) Snapshot() []Cookie {
	if j == nil {
		return nil
	}

	now := j.now()

	j.mu.Lock()
	defer j.mu.Unlock()
	return j.snapshotLocked(now)
}

// Restore replaces the jar contents with cookies and marks the jar dirty for
// auto-save. Invalid and expired records are skipped.
func (j *Jar) Restore(cookies []Cookie) {
	if j == nil {
		return
	}

	j.mu.Lock()
	j.restoreLocked(cookies, true)
	j.mu.Unlock()
}

// Clear removes all cookies. The store is not modified until Save or auto-save
// runs.
func (j *Jar) Clear() {
	if j == nil {
		return
	}

	j.mu.Lock()
	if len(j.entries) > 0 {
		j.entries = make(map[cookieKey]Cookie)
		j.afterChangeLocked()
	}
	j.mu.Unlock()
}

// Load replaces the jar contents with the value from the configured store. It
// is a no-op when no store is configured. A missing value clears the jar.
func (j *Jar) Load(ctx context.Context) error {
	if j == nil {
		return nil
	}

	j.saveMu.Lock()
	defer j.saveMu.Unlock()

	j.mu.Lock()
	store := j.store
	j.mu.Unlock()
	if store == nil {
		return nil
	}

	data, err := store.Load(ctx)
	if errors.Is(err, persist.ErrNotExist) {
		j.mu.Lock()
		j.restoreLocked(nil, false)
		j.mu.Unlock()
		return nil
	}
	if err != nil {
		return fmt.Errorf("jar: load: %w", err)
	}

	var doc document
	if err := json.Unmarshal(data, &doc); err != nil {
		return fmt.Errorf("jar: decode: %w", err)
	}
	if doc.Version != 0 && doc.Version != documentVersion {
		return fmt.Errorf("jar: unsupported document version %d", doc.Version)
	}

	j.mu.Lock()
	j.restoreLocked(doc.Cookies, false)
	j.mu.Unlock()
	return nil
}

// Save writes the current cookies to the configured store. It is a no-op when
// no store is configured.
func (j *Jar) Save(ctx context.Context) error {
	if j == nil {
		return nil
	}

	j.saveMu.Lock()
	defer j.saveMu.Unlock()

	j.mu.Lock()
	store := j.store
	if store == nil {
		j.mu.Unlock()
		return nil
	}
	doc := document{
		Version: documentVersion,
		Cookies: j.snapshotLocked(j.now()),
	}
	j.mu.Unlock()

	data, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return fmt.Errorf("jar: encode: %w", err)
	}
	if err := store.Save(ctx, data); err != nil {
		j.setAsyncError(err)
		return fmt.Errorf("jar: save: %w", err)
	}

	j.mu.Lock()
	j.lastErr = nil
	j.mu.Unlock()
	return nil
}

// Close stops auto-save and performs a final synchronous Save. The jar remains
// usable in memory afterwards, but no further background writes are scheduled.
// Close is idempotent.
func (j *Jar) Close() error {
	if j == nil {
		return nil
	}

	j.mu.Lock()
	if j.closed {
		j.mu.Unlock()
		return nil
	}
	j.closed = true
	timer := j.timer
	j.timer = nil
	j.mu.Unlock()

	if timer != nil {
		timer.Stop()
	}
	return j.Save(context.Background())
}

// Err returns the most recent asynchronous persistence error, if any. A
// successful Save clears it.
func (j *Jar) Err() error {
	if j == nil {
		return nil
	}

	j.mu.Lock()
	defer j.mu.Unlock()
	return j.lastErr
}

func (j *Jar) setCookieLocked(u *url.URL, host, scheme string, c *http.Cookie, now time.Time) bool {
	name := c.Name
	if !validCookieName(name) {
		return false
	}
	if c.Secure && scheme != "https" {
		return false
	}

	hostOnly := false
	domain := host
	if c.Domain != "" {
		domain = canonicalDomain(c.Domain)
		if domain == "" {
			return false
		}
		if net.ParseIP(host) != nil {
			if !strings.EqualFold(host, domain) {
				return false
			}
			hostOnly = true
		} else {
			if !domainMatches(host, domain, false) {
				return false
			}
			if j.psl != nil && j.psl.PublicSuffix(domain) == domain {
				return false
			}
		}
	} else {
		hostOnly = true
	}

	cookiePath := c.Path
	if cookiePath == "" || cookiePath[0] != '/' {
		cookiePath = defaultPath(u.Path)
	}

	key := cookieKey{domain: domain, path: cookiePath, name: name}

	if c.MaxAge < 0 {
		return j.deleteLocked(key)
	}

	var expires time.Time
	if c.MaxAge > 0 {
		expires = addMaxAge(now, c.MaxAge)
	} else {
		expires = c.Expires
	}
	if !expires.IsZero() && !expires.After(now) {
		return j.deleteLocked(key)
	}

	creation := now
	if old, ok := j.entries[key]; ok {
		creation = old.Creation
	}
	j.entries[key] = Cookie{
		Name:       name,
		Value:      c.Value,
		Domain:     domain,
		Path:       cookiePath,
		Expires:    expires,
		Secure:     c.Secure,
		HttpOnly:   c.HttpOnly,
		SameSite:   c.SameSite,
		HostOnly:   hostOnly,
		Creation:   creation,
		LastAccess: now,
	}
	return true
}

func (j *Jar) deleteLocked(key cookieKey) bool {
	if _, ok := j.entries[key]; !ok {
		return false
	}
	delete(j.entries, key)
	return true
}

func (j *Jar) afterChangeLocked() {
	if j.store == nil || j.closed || j.autoSave <= 0 {
		return
	}
	if j.timer == nil {
		j.timer = time.AfterFunc(j.autoSave, j.saveAsync)
		return
	}
	j.timer.Reset(j.autoSave)
}

func (j *Jar) saveAsync() {
	j.mu.Lock()
	if j.closed {
		j.mu.Unlock()
		return
	}
	j.mu.Unlock()

	_ = j.Save(context.Background())
}

func (j *Jar) setAsyncError(err error) {
	j.mu.Lock()
	j.lastErr = err
	handler := j.onError
	j.mu.Unlock()
	if handler != nil {
		handler(err)
	}
}

func (j *Jar) snapshotLocked(now time.Time) []Cookie {
	out := make([]Cookie, 0, len(j.entries))
	for key, c := range j.entries {
		if isExpired(c, now) {
			delete(j.entries, key)
			continue
		}
		out = append(out, c)
	}
	sort.Slice(out, func(a, b int) bool {
		if out[a].Domain != out[b].Domain {
			return out[a].Domain < out[b].Domain
		}
		if out[a].Path != out[b].Path {
			return out[a].Path < out[b].Path
		}
		return out[a].Name < out[b].Name
	})
	return out
}

func (j *Jar) restoreLocked(cookies []Cookie, dirty bool) {
	now := j.now()
	entries := make(map[cookieKey]Cookie, len(cookies))
	for _, c := range cookies {
		if !validCookieName(c.Name) {
			continue
		}
		domain := canonicalDomain(c.Domain)
		if domain == "" {
			continue
		}
		if c.Path == "" || c.Path[0] != '/' {
			c.Path = "/"
		}
		if isExpired(c, now) {
			continue
		}
		if c.Creation.IsZero() {
			c.Creation = now
		}
		if c.LastAccess.IsZero() {
			c.LastAccess = c.Creation
		}
		entries[cookieKey{domain: domain, path: c.Path, name: c.Name}] = c
	}
	j.entries = entries
	if dirty {
		j.afterChangeLocked()
	}
}

func configError(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrConfiguration, fmt.Sprintf(format, args...))
}

func addMaxAge(now time.Time, seconds int) time.Time {
	if seconds <= 0 {
		return time.Time{}
	}
	if int64(seconds) > int64(maxAgeLimit/time.Second) {
		return now.Add(maxAgeLimit)
	}
	return now.Add(time.Duration(seconds) * time.Second)
}

func isExpired(c Cookie, now time.Time) bool {
	return !c.Expires.IsZero() && !c.Expires.After(now)
}

func canonicalHost(host string) string {
	host = strings.Trim(host, "[]")
	return strings.TrimSuffix(strings.ToLower(host), ".")
}

func canonicalDomain(domain string) string {
	domain = strings.ToLower(strings.TrimSpace(domain))
	domain = strings.TrimPrefix(domain, ".")
	domain = strings.TrimSuffix(domain, ".")
	if domain == "" {
		return ""
	}
	return domain
}

func domainMatches(host, domain string, hostOnly bool) bool {
	if strings.EqualFold(host, domain) {
		return true
	}
	if hostOnly || net.ParseIP(host) != nil {
		return false
	}
	return strings.HasSuffix(host, "."+domain)
}

func defaultPath(p string) string {
	if p == "" || p[0] != '/' {
		return "/"
	}
	if strings.Count(p, "/") == 1 {
		return "/"
	}
	return p[:strings.LastIndex(p, "/")]
}

func pathMatches(requestPath, cookiePath string) bool {
	if requestPath == cookiePath {
		return true
	}
	if !strings.HasPrefix(requestPath, cookiePath) {
		return false
	}
	if strings.HasSuffix(cookiePath, "/") {
		return true
	}
	return len(requestPath) > len(cookiePath) && requestPath[len(cookiePath)] == '/'
}

func validCookieName(name string) bool {
	if name == "" {
		return false
	}
	for i := 0; i < len(name); i++ {
		if !isTokenChar(name[i]) {
			return false
		}
	}
	return true
}

func isTokenChar(c byte) bool {
	switch c {
	case '!', '#', '$', '%', '&', '\'', '*', '+', '-', '.', '^', '_', '`', '|', '~':
		return true
	}
	if c >= '0' && c <= '9' {
		return true
	}
	if c >= 'a' && c <= 'z' {
		return true
	}
	if c >= 'A' && c <= 'Z' {
		return true
	}
	return false
}
