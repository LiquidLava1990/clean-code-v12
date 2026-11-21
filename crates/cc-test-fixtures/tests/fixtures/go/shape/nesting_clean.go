// Package shape — sample clean cc.shape.nesting_depth (early returns).
package shape

// Classify returns ids of gold-tier active US records.
func Classify(records []Record) []string {
	out := []string{}
	for _, r := range records {
		if isGoldUsActive(r) {
			out = append(out, r.ID)
		}
	}
	return out
}

func isGoldUsActive(r Record) bool {
	if r.ID == "" {
		return false
	}
	if r.Status != "active" {
		return false
	}
	if r.Score <= 0 {
		return false
	}
	return r.Region == "us" && r.Tier == "gold"
}
