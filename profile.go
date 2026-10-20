package impersonate

import (
	"fmt"
	"sort"
	"strings"

	"github.com/bogdanfinn/tls-client/profiles"
)

const (
	defaultChromeProfile  = "chrome_150"
	defaultFirefoxProfile = "firefox_147"
	defaultSafariProfile  = "safari_16_0"
)

// Profile selects a concrete browser TLS/HTTP2 fingerprint snapshot.
//
// A Profile is a named snapshot, not a live browser version range. For example
// Chrome() returns a specific profile such as chrome_150; it must not be
// interpreted as an exact fingerprint for every Chrome release.
type Profile struct {
	name          string
	clientProfile profiles.ClientProfile
	headerOrder   []string
}

// Name returns the stable profile identifier from the upstream profile table,
// such as "chrome_150" or "firefox_147".
func (p Profile) Name() string { return p.name }

// String returns the profile name.
func (p Profile) String() string { return p.name }

// HeaderOrder returns a copy of the default request header order associated
// with the profile. It may be overridden with WithHeaderOrder.
func (p Profile) HeaderOrder() []string {
	return append([]string(nil), p.headerOrder...)
}

// Chrome returns a concrete Chrome profile snapshot.
//
// The current default is chrome_150, matching the upstream tls-client default.
// Use ChromeVersion or ProfileByName to choose another concrete snapshot.
func Chrome() Profile { return mustProfile(defaultChromeProfile) }

// Firefox returns a concrete Firefox profile snapshot.
//
// The current default is firefox_147. Use FirefoxVersion or ProfileByName to
// choose another concrete snapshot.
func Firefox() Profile { return mustProfile(defaultFirefoxProfile) }

// Safari returns a concrete desktop Safari profile snapshot.
//
// The upstream profile table currently exposes safari_16_0 for desktop Safari;
// newer mobile versions are available through ProfileByName or SafariVersion.
func Safari() Profile { return mustProfile(defaultSafariProfile) }

// ChromeVersion returns a concrete Chrome profile by version, for example
// "131" or "chrome_131".
func ChromeVersion(version string) (Profile, error) {
	return versionedProfile("chrome", version)
}

// FirefoxVersion returns a concrete Firefox profile by version, for example
// "147" or "firefox_147".
func FirefoxVersion(version string) (Profile, error) {
	return versionedProfile("firefox", version)
}

// SafariVersion returns a concrete Safari profile by version, for example
// "16.0" or "safari_16_0". Mobile profiles can be selected with names such as
// "ios_26_0" or "safari_ios_26_0".
func SafariVersion(version string) (Profile, error) {
	return versionedProfile("safari", version)
}

// ProfileByName resolves any profile exposed by the upstream tls-client
// profile table. Names are case-insensitive. Examples include "chrome_131",
// "firefox_147", "safari_16_0", and "safari_ios_26_0".
func ProfileByName(name string) (Profile, error) {
	normalized := normalizeProfileName(name)
	clientProfile, ok := profiles.MappedTLSClients[normalized]
	if !ok {
		return Profile{}, profileError("unknown profile %q", name)
	}
	return buildProfile(normalized, clientProfile), nil
}

// Profiles returns the sorted names of all available profiles.
func Profiles() []string {
	names := make([]string, 0, len(profiles.MappedTLSClients))
	for name := range profiles.MappedTLSClients {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// NewProfile wraps an upstream tls-client profile as a Profile.
//
// It is intended for advanced users who construct custom ClientHello and
// HTTP/2 settings with tls-client's profiles.NewClientProfile. The name is used
// for diagnostics and for selecting a default header order.
func NewProfile(name string, clientProfile profiles.ClientProfile) (Profile, error) {
	normalized := normalizeProfileName(name)
	if normalized == "" {
		return Profile{}, configError("profile name must not be empty")
	}
	return buildProfile(normalized, clientProfile), nil
}

func versionedProfile(family, version string) (Profile, error) {
	version = strings.ToLower(strings.TrimSpace(version))
	version = strings.TrimPrefix(version, family+"_")
	version = strings.ReplaceAll(version, ".", "_")
	if version == "" {
		return Profile{}, profileError("%s version must not be empty", family)
	}
	return ProfileByName(family + "_" + version)
}

func mustProfile(name string) Profile {
	p, err := ProfileByName(name)
	if err != nil {
		panic(err)
	}
	return p
}

func buildProfile(name string, clientProfile profiles.ClientProfile) Profile {
	return Profile{
		name:          name,
		clientProfile: clientProfile,
		headerOrder:   defaultHeaderOrder(name),
	}
}

func normalizeProfileName(name string) string {
	return strings.ToLower(strings.TrimSpace(name))
}

func defaultHeaderOrder(name string) []string {
	switch {
	case strings.HasPrefix(name, "chrome_"), strings.HasPrefix(name, "brave_"):
		return []string{
			"host",
			"connection",
			"content-length",
			"cache-control",
			"sec-ch-ua",
			"sec-ch-ua-mobile",
			"sec-ch-ua-platform",
			"upgrade-insecure-requests",
			"user-agent",
			"accept",
			"sec-fetch-site",
			"sec-fetch-mode",
			"sec-fetch-user",
			"sec-fetch-dest",
			"referer",
			"accept-encoding",
			"accept-language",
			"cookie",
			"priority",
		}
	case strings.HasPrefix(name, "firefox_"):
		return []string{
			"host",
			"user-agent",
			"accept",
			"accept-language",
			"accept-encoding",
			"dnt",
			"upgrade-insecure-requests",
			"sec-fetch-dest",
			"sec-fetch-mode",
			"sec-fetch-site",
			"sec-fetch-user",
			"referer",
			"cookie",
			"connection",
			"content-length",
			"cache-control",
			"pragma",
			"priority",
		}
	case strings.HasPrefix(name, "safari_"):
		return []string{
			"host",
			"accept",
			"accept-encoding",
			"accept-language",
			"user-agent",
			"connection",
			"cookie",
			"referer",
			"content-length",
			"cache-control",
			"pragma",
			"priority",
		}
	default:
		return nil
	}
}

func (p Profile) validate() error {
	if p.name == "" {
		return configError("profile must not be zero; use Chrome(), Firefox(), Safari(), or ProfileByName")
	}
	if p.clientProfile.GetClientHelloStr() == "" {
		return configError("profile %q has an empty ClientHello", p.name)
	}
	return nil
}

func (p Profile) describe() string {
	return fmt.Sprintf("%s (%s)", p.name, p.clientProfile.GetClientHelloStr())
}
