package impersonate_test

import (
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/Xwudao/go-req-ext/impersonate"
)

func TestBuiltInProfilesAreConcreteSnapshots(t *testing.T) {
	tests := []struct {
		name    string
		profile impersonate.Profile
		want    string
	}{
		{name: "chrome", profile: impersonate.Chrome(), want: "chrome_150"},
		{name: "firefox", profile: impersonate.Firefox(), want: "firefox_147"},
		{name: "safari", profile: impersonate.Safari(), want: "safari_16_0"},
	}
	for _, tc := range tests {
		if got := tc.profile.Name(); got != tc.want {
			t.Errorf("%s name = %q, want %q", tc.name, got, tc.want)
		}
		if got := tc.profile.String(); got != tc.want {
			t.Errorf("%s String = %q", tc.name, got)
		}
		if len(tc.profile.HeaderOrder()) == 0 {
			t.Errorf("%s has no default header order", tc.name)
		}
	}
}

func TestVersionedProfiles(t *testing.T) {
	tests := []struct {
		name string
		got  func() (impersonate.Profile, error)
		want string
	}{
		{name: "chrome", got: func() (impersonate.Profile, error) { return impersonate.ChromeVersion("131") }, want: "chrome_131"},
		{name: "chrome prefixed", got: func() (impersonate.Profile, error) { return impersonate.ChromeVersion("chrome_133") }, want: "chrome_133"},
		{name: "firefox", got: func() (impersonate.Profile, error) { return impersonate.FirefoxVersion("147") }, want: "firefox_147"},
		{name: "safari", got: func() (impersonate.Profile, error) { return impersonate.SafariVersion("16.0") }, want: "safari_16_0"},
		{name: "safari ios", got: func() (impersonate.Profile, error) { return impersonate.SafariVersion("ios_26_0") }, want: "safari_ios_26_0"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			profile, err := tc.got()
			if err != nil {
				t.Fatalf("profile: %v", err)
			}
			if profile.Name() != tc.want {
				t.Fatalf("name = %q, want %q", profile.Name(), tc.want)
			}
		})
	}
}

func TestProfileByName(t *testing.T) {
	profile, err := impersonate.ProfileByName(" CHROME_150 ")
	if err != nil {
		t.Fatalf("ProfileByName: %v", err)
	}
	if profile.Name() != "chrome_150" {
		t.Fatalf("name = %q", profile.Name())
	}
	if !slices.Contains(impersonate.Profiles(), "chrome_150") {
		t.Fatal("Profiles does not list chrome_150")
	}
}

func TestUnknownProfile(t *testing.T) {
	_, err := impersonate.ProfileByName("netscape_4")
	if !errors.Is(err, impersonate.ErrUnsupportedProfile) {
		t.Fatalf("err = %v, want ErrUnsupportedProfile", err)
	}
}

func TestZeroProfileRejected(t *testing.T) {
	_, err := impersonate.New(impersonate.Profile{})
	if !errors.Is(err, impersonate.ErrConfiguration) {
		t.Fatalf("err = %v, want ErrConfiguration", err)
	}
}

func TestInvalidOptions(t *testing.T) {
	tests := []struct {
		name string
		opt  impersonate.Option
	}{
		{name: "nil option", opt: nil},
		{name: "nil root CAs", opt: impersonate.WithRootCAs(nil)},
		{name: "negative idle timeout", opt: impersonate.WithIdleConnTimeout(-time.Second)},
		{name: "negative handshake timeout", opt: impersonate.WithHandshakeTimeout(-time.Second)},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := impersonate.New(impersonate.Chrome(), tc.opt)
			if !errors.Is(err, impersonate.ErrConfiguration) {
				t.Fatalf("err = %v, want ErrConfiguration", err)
			}
		})
	}
}
