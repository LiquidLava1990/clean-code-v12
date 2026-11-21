pub async fn fetch(url: &str) -> String {
    String::from(url)
}

pub unsafe fn dangerous(p: *const u8) -> u8 {
    *p
}

pub const fn double(x: i32) -> i32 {
    x * 2
}
