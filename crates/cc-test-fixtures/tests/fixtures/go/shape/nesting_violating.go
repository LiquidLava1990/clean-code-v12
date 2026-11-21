// Package shape — sample violating cc.shape.nesting_depth (5 deep).
package shape

// Classify returns ids of gold-tier active US records — too nested.
func Classify(records []Record) []string {
	out := []string{}
	for _, r := range records {
		if r.ID != "" {
			if r.Status == "active" {
				if r.Score > 0 {
					if r.Region == "us" {
						if r.Tier == "gold" {
							out = append(out, r.ID)
						}
					}
				}
			}
		}
	}
	return out
}
