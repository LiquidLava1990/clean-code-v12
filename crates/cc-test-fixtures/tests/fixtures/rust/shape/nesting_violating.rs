//! Sample violating cc.shape.nesting_depth: 5 levels deep.

pub struct Record {
    pub id: String,
    pub active: bool,
    pub score: i64,
    pub region: String,
    pub tier: String,
}

pub fn classify(records: &[Record]) -> Vec<String> {
    let mut out = Vec::new();
    for r in records {
        if !r.id.is_empty() {
            if r.active {
                if r.score > 0 {
                    if r.region == "us" {
                        if r.tier == "gold" {
                            out.push(r.id.clone());
                        }
                    }
                }
            }
        }
    }
    out
}
