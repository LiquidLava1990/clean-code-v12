// Package shape — sample clean cc.shape.fn_length (composed helpers).
package shape

// Record models an inbound record.
type Record struct {
	ID     string
	Status string
	Score  int
}

// ProcessRecords returns enriched, non-rejected records.
func ProcessRecords(records []Record) []Record {
	out := make([]Record, 0, len(records))
	for _, r := range records {
		if isRejected(r) {
			continue
		}
		out = append(out, enrich(r))
	}
	return out
}

func isRejected(r Record) bool {
	return r.Status == "rejected"
}

func enrich(r Record) Record {
	r.Score = r.Score / 100
	return r
}
