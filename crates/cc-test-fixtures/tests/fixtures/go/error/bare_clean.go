// Package errcase — sample clean cc.error.bare (typed wrap + action).
package errcase

import (
	"fmt"
	"os"
)

// FixtureLoadError wraps an underlying load failure.
type FixtureLoadError struct {
	Path string
	Err  error
}

// Error returns the actionable message.
func (e *FixtureLoadError) Error() string {
	return fmt.Sprintf(
		"failed to read fixture path_kind=%T; verify the path exists and is readable: %v",
		e.Path, e.Err,
	)
}

// Unwrap exposes the underlying error.
func (e *FixtureLoadError) Unwrap() error { return e.Err }

// SafeRead reads a file with a typed, actionable error on failure.
func SafeRead(path string) ([]byte, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, &FixtureLoadError{Path: path, Err: err}
	}
	return data, nil
}
