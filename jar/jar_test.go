package jar

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"sync"
	"testing"
	"time"

	"github.com/Xwudao/go-req-ext/persist"
)

func mustURL(t *testing.T, raw string) *url.URL {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	return u
}

func newJar(t *testing.T, opts ...Option) (*Jar, *time.Time) {
	t.Helper()
	j, err := New(opts...)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	j.now = func() time.Time { return now }
	return j, &now
}

func cookieMap(cookies []*http.Cookie) map[string]string {
	out := make(map[string]string, len(cookies))
	for _, c := range cookies {
		out[c.Name] = c.Value
	}
	return out
}

func TestSetAndGet(t *testing.T) {
	j, _ := newJar(t)
	origin := mustURL(t, "https://www.example.com/app/page")

	j.SetCookies(origin, []*http.Cookie{
		{Name: "a", Value: "1"},
		{Name: "b", Value: "2"},
	})

	got := cookieMap(j.Cookies(mustURL(t, "https://www.example.com/app/other")))
	if got["a"] != "1" || got["b"] != "2" {
		t.Fatalf("Cookies = %v", got)
	}

	// The default path is /app, so it must not be sent to the site root.
	if got := j.Cookies(mustURL(t, "https://www.example.com/")); len(got) != 0 {
		t.Fatalf("Cookies at / = %v, want none", got)
	}

	// Host-only cookies are not sent to sibling hosts.
	if got := j.Cookies(mustURL(t, "https://api.example.com/app/x")); len(got) != 0 {
		t.Fatalf("Cookies at api host = %v, want none", got)
	}
}

func TestDomainCookies(t *testing.T) {
	j, _ := newJar(t)
	origin := mustURL(t, "https://www.example.com/")

	j.SetCookies(origin, []*http.Cookie{
		{Name: "wide", Value: "1", Domain: ".example.com", Path: "/"},
	})

	cases := []struct {
		url  string
		want bool
	}{
		{"https://example.com/", true},
		{"https://api.example.com/", true},
		{"https://www.example.com/", true},
		{"https://badexample.com/", false},
		{"https://example.com.evil.test/", false},
	}
	for _, tc := range cases {
		_, ok := cookieMap(j.Cookies(mustURL(t, tc.url)))["wide"]
		if ok != tc.want {
			t.Errorf("Cookies(%s) present = %v, want %v", tc.url, ok, tc.want)
		}
	}

	snapshot := j.Snapshot()
	if len(snapshot) != 1 || snapshot[0].HostOnly {
		t.Fatalf("Snapshot = %+v, want one domain cookie", snapshot)
	}
}

func TestPublicSuffixList(t *testing.T) {
	j, _ := newJar(t, WithPublicSuffixList(testSuffixList{}))
	origin := mustURL(t, "https://www.example.com/")

	j.SetCookies(origin, []*http.Cookie{
		{Name: "bad", Value: "1", Domain: "com", Path: "/"},
		{Name: "good", Value: "1", Domain: "example.com", Path: "/"},
	})

	names := cookieMap(j.Cookies(mustURL(t, "https://www.example.com/")))
	if _, ok := names["bad"]; ok {
		t.Fatal("cookie for public suffix was accepted")
	}
	if names["good"] != "1" {
		t.Fatalf("Cookies = %v, want good=1", names)
	}
}

func TestSecureCookies(t *testing.T) {
	j, _ := newJar(t)

	// Secure cookies received over plain HTTP are ignored.
	j.SetCookies(mustURL(t, "http://example.com/"), []*http.Cookie{
		{Name: "s", Value: "1", Secure: true, Path: "/"},
	})
	if got := j.Cookies(mustURL(t, "https://example.com/")); len(got) != 0 {
		t.Fatalf("Cookies = %v, want none", got)
	}

	j.SetCookies(mustURL(t, "https://example.com/"), []*http.Cookie{
		{Name: "s", Value: "1", Secure: true, Path: "/"},
	})
	if got := cookieMap(j.Cookies(mustURL(t, "http://example.com/"))); len(got) != 0 {
		t.Fatalf("Cookies over http = %v, want none", got)
	}
	if got := cookieMap(j.Cookies(mustURL(t, "https://example.com/"))); got["s"] != "1" {
		t.Fatalf("Cookies over https = %v, want s=1", got)
	}
}

func TestExpiryAndMaxAge(t *testing.T) {
	j, now := newJar(t)
	u := mustURL(t, "https://example.com/")

	// Already expired cookies are not stored.
	j.SetCookies(u, []*http.Cookie{
		{Name: "old", Value: "1", Path: "/", Expires: now.Add(-time.Hour)},
	})
	if len(j.Snapshot()) != 0 {
		t.Fatalf("Snapshot = %+v, want empty", j.Snapshot())
	}

	// Max-Age is relative and expires on read.
	j.SetCookies(u, []*http.Cookie{
		{Name: "short", Value: "1", Path: "/", MaxAge: 1},
	})
	if _, ok := cookieMap(j.Cookies(u))["short"]; !ok {
		t.Fatal("short-lived cookie missing")
	}
	*now = now.Add(2 * time.Second)
	if got := j.Cookies(u); len(got) != 0 {
		t.Fatalf("Cookies = %v, want none after expiry", got)
	}

	// Max-Age < 0 deletes a matching cookie.
	j.SetCookies(u, []*http.Cookie{{Name: "del", Value: "1", Path: "/"}})
	j.SetCookies(u, []*http.Cookie{{Name: "del", Value: "", Path: "/", MaxAge: -1}})
	if got := j.Cookies(u); len(got) != 0 {
		t.Fatalf("Cookies = %v, want none after delete", got)
	}
}

func TestCookieOrder(t *testing.T) {
	j, now := newJar(t)
	u := mustURL(t, "https://example.com/a/b/c")

	j.SetCookies(u, []*http.Cookie{{Name: "root", Value: "1", Path: "/"}})
	*now = now.Add(time.Second)
	j.SetCookies(u, []*http.Cookie{{Name: "a", Value: "1", Path: "/a"}})
	*now = now.Add(time.Second)
	j.SetCookies(u, []*http.Cookie{{Name: "ab", Value: "1", Path: "/a/b"}})
	*now = now.Add(time.Second)
	j.SetCookies(u, []*http.Cookie{{Name: "second", Value: "1", Path: "/"}})

	got := j.Cookies(u)
	want := []string{"ab", "a", "root", "second"}
	if len(got) != len(want) {
		t.Fatalf("Cookies = %v, want %v", got, want)
	}
	for i := range want {
		if got[i].Name != want[i] {
			t.Fatalf("Cookies[%d] = %q, want %q (all: %v)", i, got[i].Name, want[i], got)
		}
	}
}

func TestOverwritePreservesCreation(t *testing.T) {
	j, now := newJar(t)
	u := mustURL(t, "https://example.com/")
	j.SetCookies(u, []*http.Cookie{{Name: "a", Value: "1", Path: "/"}})
	created := j.Snapshot()[0].Creation

	*now = now.Add(time.Hour)
	j.SetCookies(u, []*http.Cookie{{Name: "a", Value: "2", Path: "/"}})

	snapshot := j.Snapshot()
	if len(snapshot) != 1 || snapshot[0].Value != "2" {
		t.Fatalf("Snapshot = %+v", snapshot)
	}
	if !snapshot[0].Creation.Equal(created) {
		t.Fatalf("Creation = %v, want %v", snapshot[0].Creation, created)
	}
}

func TestInvalidCookiesIgnored(t *testing.T) {
	j, _ := newJar(t)
	u := mustURL(t, "https://example.com/")
	j.SetCookies(u, []*http.Cookie{
		nil,
		{Name: "", Value: "x", Path: "/"},
		{Name: "bad name", Value: "x", Path: "/"},
		{Name: "bad,name", Value: "x", Path: "/"},
	})
	if got := j.Snapshot(); len(got) != 0 {
		t.Fatalf("Snapshot = %+v, want empty", got)
	}
}

func TestRestoreAndClear(t *testing.T) {
	j, now := newJar(t)
	u := mustURL(t, "https://example.com/")

	j.Restore([]Cookie{
		{Name: "a", Value: "1", Domain: "example.com", Path: "/", HostOnly: true, Creation: *now},
		{Name: "expired", Value: "1", Domain: "example.com", Path: "/", Expires: now.Add(-time.Hour)},
		{Name: "", Value: "invalid", Domain: "example.com", Path: "/"},
	})
	if got := cookieMap(j.Cookies(u)); got["a"] != "1" || len(got) != 1 {
		t.Fatalf("Cookies = %v", got)
	}

	j.Clear()
	if got := j.Snapshot(); len(got) != 0 {
		t.Fatalf("Snapshot = %+v, want empty", got)
	}
}

func TestPersistenceRoundTrip(t *testing.T) {
	ctx := context.Background()
	store := persist.NewMemory()

	j, err := Open(ctx, WithStore(store))
	if err != nil {
		t.Fatal(err)
	}
	u := mustURL(t, "https://example.com/")
	j.SetCookies(u, []*http.Cookie{
		{Name: "session", Value: "1", Path: "/"},
		{Name: "persistent", Value: "2", Path: "/", Expires: time.Now().Add(time.Hour)},
	})
	j.SetCookies(u, []*http.Cookie{
		{Name: "wide", Value: "3", Domain: "example.com", Path: "/", Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode},
	})
	if err := j.Save(ctx); err != nil {
		t.Fatal(err)
	}

	loaded, err := Open(ctx, WithStore(store))
	if err != nil {
		t.Fatal(err)
	}
	got := cookieMap(loaded.Cookies(u))
	if got["session"] != "1" || got["persistent"] != "2" || got["wide"] != "3" {
		t.Fatalf("Cookies after load = %v", got)
	}

	snapshot := loaded.Snapshot()
	if len(snapshot) != 3 {
		t.Fatalf("Snapshot = %+v", snapshot)
	}
	for _, c := range snapshot {
		if c.Name == "wide" {
			if !c.Secure || !c.HttpOnly || c.SameSite != http.SameSiteLaxMode {
				t.Fatalf("metadata not preserved: %+v", c)
			}
			if c.HostOnly {
				t.Fatalf("domain cookie became host-only: %+v", c)
			}
		}
	}
}

func TestLoadMissingClears(t *testing.T) {
	ctx := context.Background()
	j, err := New(WithStore(persist.NewMemory()))
	if err != nil {
		t.Fatal(err)
	}
	u := mustURL(t, "https://example.com/")
	j.SetCookies(u, []*http.Cookie{{Name: "a", Value: "1", Path: "/"}})
	if len(j.Snapshot()) != 1 {
		t.Fatal("cookie not stored")
	}
	if err := j.Load(ctx); err != nil {
		t.Fatal(err)
	}
	if got := j.Snapshot(); len(got) != 0 {
		t.Fatalf("Snapshot = %+v, want empty", got)
	}
}

func TestNoStore(t *testing.T) {
	ctx := context.Background()
	j, _ := newJar(t)
	if err := j.Load(ctx); err != nil {
		t.Fatalf("Load without store = %v", err)
	}
	if err := j.Save(ctx); err != nil {
		t.Fatalf("Save without store = %v", err)
	}
	if err := j.Close(); err != nil {
		t.Fatalf("Close without store = %v", err)
	}
	if err := j.Close(); err != nil {
		t.Fatalf("second Close = %v", err)
	}
}

func TestAutoSave(t *testing.T) {
	store := newSignalStore()
	j, err := New(WithStore(store), WithAutoSave(10*time.Millisecond))
	if err != nil {
		t.Fatal(err)
	}
	defer j.Close()

	j.SetCookies(mustURL(t, "https://example.com/"), []*http.Cookie{
		{Name: "a", Value: "1", Path: "/"},
	})

	select {
	case <-store.saved:
	case <-time.After(3 * time.Second):
		t.Fatal("auto-save did not run")
	}

	loaded, err := Open(context.Background(), WithStore(store))
	if err != nil {
		t.Fatal(err)
	}
	if got := cookieMap(loaded.Cookies(mustURL(t, "https://example.com/"))); got["a"] != "1" {
		t.Fatalf("Cookies = %v", got)
	}
}

func TestAutoSaveError(t *testing.T) {
	boom := errors.New("boom")
	reported := make(chan error, 1)
	store := persist.StoreFunc{
		LoadFunc:   func(context.Context) ([]byte, error) { return nil, persist.ErrNotExist },
		SaveFunc:   func(context.Context, []byte) error { return boom },
		DeleteFunc: func(context.Context) error { return nil },
	}
	j, err := New(
		WithStore(store),
		WithAutoSave(10*time.Millisecond),
		WithErrorHandler(func(err error) { reported <- err }),
	)
	if err != nil {
		t.Fatal(err)
	}
	defer j.Close()

	j.SetCookies(mustURL(t, "https://example.com/"), []*http.Cookie{{Name: "a", Value: "1", Path: "/"}})
	select {
	case err := <-reported:
		if !errors.Is(err, boom) {
			t.Fatalf("reported error = %v, want boom", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("error handler was not called")
	}
	if !errors.Is(j.Err(), boom) {
		t.Fatalf("Err = %v, want boom", j.Err())
	}
}

func TestCloseFlushes(t *testing.T) {
	store := newSignalStore()
	j, err := New(WithStore(store), WithAutoSave(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	j.SetCookies(mustURL(t, "https://example.com/"), []*http.Cookie{{Name: "a", Value: "1", Path: "/"}})
	if err := j.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Load(context.Background()); err != nil {
		t.Fatalf("store not flushed: %v", err)
	}
}

func TestConcurrentAccess(t *testing.T) {
	j, _ := newJar(t)
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			u := mustURL(t, "https://example.com/a/b")
			for k := 0; k < 100; k++ {
				j.SetCookies(u, []*http.Cookie{{Name: "a", Value: "1", Path: "/a"}})
				_ = j.Cookies(u)
				_ = j.Snapshot()
			}
		}(i)
	}
	wg.Wait()
}

func TestIPv6Host(t *testing.T) {
	j, _ := newJar(t)
	u := mustURL(t, "http://[::1]:8080/")
	j.SetCookies(u, []*http.Cookie{{Name: "a", Value: "1", Path: "/"}})
	if got := cookieMap(j.Cookies(u)); got["a"] != "1" {
		t.Fatalf("Cookies = %v", got)
	}
	if got := j.Cookies(mustURL(t, "http://[::2]:8080/")); len(got) != 0 {
		t.Fatalf("Cookies for other IPv6 host = %v", got)
	}
}

func TestHelpers(t *testing.T) {
	pathCases := []struct {
		in, want string
	}{
		{"", "/"},
		{"abc", "/"},
		{"/", "/"},
		{"/a", "/"},
		{"/a/b", "/a"},
	}
	for _, tc := range pathCases {
		if got := defaultPath(tc.in); got != tc.want {
			t.Errorf("defaultPath(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}

	matchCases := []struct {
		request, cookie string
		want            bool
	}{
		{"/", "/", true},
		{"/a", "/a", true},
		{"/a/b", "/a", true},
		{"/ab", "/a", false},
		{"/a/b", "/a/", true},
		{"/a", "/a/", false},
	}
	for _, tc := range matchCases {
		if got := pathMatches(tc.request, tc.cookie); got != tc.want {
			t.Errorf("pathMatches(%q, %q) = %v, want %v", tc.request, tc.cookie, got, tc.want)
		}
	}

	if got := addMaxAge(time.Unix(0, 0), int(^uint(0)>>1)); got.IsZero() {
		t.Fatal("addMaxAge overflowed")
	}
}

func TestOptions(t *testing.T) {
	if _, err := New(nil); !errors.Is(err, ErrConfiguration) {
		t.Fatalf("New(nil) = %v, want ErrConfiguration", err)
	}
	if _, err := New(WithStore(nil)); !errors.Is(err, ErrConfiguration) {
		t.Fatalf("WithStore(nil) = %v, want ErrConfiguration", err)
	}
	if _, err := New(WithAutoSave(-time.Second)); !errors.Is(err, ErrConfiguration) {
		t.Fatalf("WithAutoSave(-1) = %v, want ErrConfiguration", err)
	}
	if _, err := New(WithAutoSave(time.Second)); !errors.Is(err, ErrConfiguration) {
		t.Fatalf("WithAutoSave without store = %v, want ErrConfiguration", err)
	}
}

type testSuffixList struct{}

func (testSuffixList) String() string { return "test" }

func (testSuffixList) PublicSuffix(domain string) string {
	if domain == "com" || domain == "test" {
		return domain
	}
	for i := 0; i < len(domain); i++ {
		if domain[i] == '.' {
			return domain[i+1:]
		}
	}
	return domain
}

type signalStore struct {
	mu     sync.Mutex
	data   []byte
	exists bool
	saved  chan struct{}
}

func newSignalStore() *signalStore {
	return &signalStore{saved: make(chan struct{}, 1)}
}

func (s *signalStore) Load(ctx context.Context) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.exists {
		return nil, persist.ErrNotExist
	}
	return append([]byte(nil), s.data...), nil
}

func (s *signalStore) Save(ctx context.Context, data []byte) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.Lock()
	s.data = append([]byte(nil), data...)
	s.exists = true
	s.mu.Unlock()
	select {
	case s.saved <- struct{}{}:
	default:
	}
	return nil
}

func (s *signalStore) Delete(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.Lock()
	s.data = nil
	s.exists = false
	s.mu.Unlock()
	return nil
}
