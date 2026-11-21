#[inline]
#[must_use]
pub fn squared(x: i32) -> i32 {
    x * x
}

#[derive(Debug, Clone)]
pub struct Holder {
    value: i32,
}
