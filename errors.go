package impersonate

import (
	"errors"
	"fmt"
)

var (
	// ErrConfiguration reports invalid impersonate.Transport configuration.
	ErrConfiguration = errors.New("impersonate: configuration error")

	// ErrUnsupportedProfile reports an unknown browser profile name.
	ErrUnsupportedProfile = errors.New("impersonate: unsupported profile")
)

func configError(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrConfiguration, fmt.Sprintf(format, args...))
}

func profileError(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrUnsupportedProfile, fmt.Sprintf(format, args...))
}
