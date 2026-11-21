//! Sample violating cc.shape.fn_length: function exceeds 50 logical LOC.

#[derive(Debug, Default, Clone)]
pub struct Record {
    pub id: String,
    pub status: String,
    pub score: i64,
    pub region: String,
    pub tier: String,
}

pub fn process_records(records: &[Record]) -> Vec<Record> {
    let mut out: Vec<Record> = Vec::new();
    let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
    let mut skipped = 0;
    let mut accepted = 0;
    let mut rejected = 0;
    let mut flagged = 0;
    let mut queued = 0;
    let mut deferred = 0;
    let mut audited = 0;
    for r in records {
        if r.id.is_empty() {
            skipped += 1;
            continue;
        }
        if seen.contains(&r.id) {
            skipped += 1;
            continue;
        }
        seen.insert(r.id.clone());
        if r.status == "rejected" {
            rejected += 1;
            continue;
        }
        if r.status == "flagged" {
            flagged += 1;
            out.push(Record { id: r.id.clone(), status: "flag".into(), ..Default::default() });
            continue;
        }
        if r.status == "queued" {
            queued += 1;
            out.push(Record { id: r.id.clone(), status: "queue".into(), ..Default::default() });
            continue;
        }
        if r.status == "deferred" {
            deferred += 1;
            out.push(Record { id: r.id.clone(), status: "defer".into(), ..Default::default() });
            continue;
        }
        if r.status == "audit" {
            audited += 1;
            out.push(Record { id: r.id.clone(), status: "audit".into(), ..Default::default() });
            continue;
        }
        accepted += 1;
        out.push(r.clone());
    }
    let _ = (skipped, accepted, rejected, flagged, queued, deferred, audited);
    out
}
