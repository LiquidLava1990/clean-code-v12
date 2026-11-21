// Package shape — sample clean cc.shape.dead_code (every branch reachable).
package shape

// Label returns a tier label for the given numeric score.
func Label(score int) string {
	if score >= 90 {
		return "gold"
	}
	if score >= 50 {
		return "silver"
	}
	return "bronze"
}

// Render applies Label across a slice of scores.
func Render(scores []int) []string {
	out := make([]string, 0, len(scores))
	for _, s := range scores {
		out = append(out, Label(s))
	}
	return out
}
