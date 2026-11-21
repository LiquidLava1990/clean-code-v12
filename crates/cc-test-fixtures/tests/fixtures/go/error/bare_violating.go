// Package errcase — sample violating cc.error.bare (swallowed error).
package errcase

import "os"

// SafeRead reads a file but swallows the error — antipattern.
func SafeRead(path string) []byte {
	data, _ := os.ReadFile(path) // nolint:errcheck — intentional swallow.
	return data
}
