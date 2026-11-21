//! Sample clean cc.shape.dead_code: every branch reachable, every fn used.

pub fn label(score: i64) -> &'static str {
    if score >= 90 {
        return "gold";
    }
    if score >= 50 {
        return "silver";
    }
    "bronze"
}

pub fn render(scores: &[i64]) -> Vec<&'static str> {
    scores.iter().copied().map(label).collect()
}
