//! Sample clean cc.shape.nesting_depth: early returns keep depth shallow.

pub struct Record {
    pub id: String,
    pub active: bool,
    pub score: i64,
    pub region: String,
    pub tier: String,
}

pub fn classify(records: &[Record]) -> Vec<String> {
    records
        .iter()
        .filter(|r| is_gold_us_active(r))
        .map(|r| r.id.clone())
        .collect()
}

fn is_gold_us_active(record: &Record) -> bool {
    if record.id.is_empty() {
        return false;
    }
    if !record.active {
        return false;
    }
    if record.score <= 0 {
        return false;
    }
    record.region == "us" && record.tier == "gold"
}
