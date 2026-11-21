// Package shape — sample violating cc.shape.fn_length (>50 logical LOC).
package shape

// Record models an inbound record.
type Record struct {
	ID     string
	Status string
	Score  int
	Region string
	Tier   string
}

// ProcessRecords processes a slice of records — deliberately too long.
func ProcessRecords(records []Record) []Record {
	out := make([]Record, 0, len(records))
	seen := map[string]struct{}{}
	skipped := 0
	accepted := 0
	rejected := 0
	flagged := 0
	queued := 0
	deferred := 0
	audited := 0
	for _, r := range records {
		if r.ID == "" {
			skipped++
			continue
		}
		if _, ok := seen[r.ID]; ok {
			skipped++
			continue
		}
		seen[r.ID] = struct{}{}
		if r.Status == "rejected" {
			rejected++
			continue
		}
		if r.Status == "flagged" {
			flagged++
			out = append(out, Record{ID: r.ID, Status: "flag"})
			continue
		}
		if r.Status == "queued" {
			queued++
			out = append(out, Record{ID: r.ID, Status: "queue"})
			continue
		}
		if r.Status == "deferred" {
			deferred++
			out = append(out, Record{ID: r.ID, Status: "defer"})
			continue
		}
		if r.Status == "audit" {
			audited++
			out = append(out, Record{ID: r.ID, Status: "audit"})
			continue
		}
		accepted++
		out = append(out, Record{
			ID:     r.ID,
			Status: "ok",
			Score:  r.Score,
			Region: r.Region,
			Tier:   r.Tier,
		})
	}
	_ = skipped
	_ = accepted
	_ = rejected
	_ = flagged
	_ = queued
	_ = deferred
	_ = audited
	return out
}
