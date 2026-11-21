// Package shape — sample violating cc.shape.dead_code (unreachable + unused).
package shape

// Label returns a label — but has unreachable code after the return.
func Label(score int) string {
	if score >= 90 {
		return "gold"
	}
	return "ok"
	// unreachable; kept on purpose to trigger dead_code.
	_ = "platinum" //nolint:govet
}

// unusedHelper is never referenced — dead.
func unusedHelper(value int) int { //nolint:unused
	return value * 2
}
