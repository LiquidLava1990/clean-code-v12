//! Sample violating cc.shape.dead_code: unreachable expression + unused fn.

pub fn label(score: i64) -> &'static str {
    if score >= 90 {
        return "gold";
    }
    return "ok";
    // unreachable — kept on purpose to trigger dead_code.
    #[allow(unreachable_code)]
    "platinum"
}

#[allow(dead_code)]
fn unused_helper(value: i64) -> i64 {
    // Never referenced anywhere — dead.
    value * 2
}
