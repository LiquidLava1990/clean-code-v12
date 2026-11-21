pub fn classify(n: i32) -> &'static str {
    match n {
        0 => "zero",
        1 | 2 | 3 => "small",
        _ if n < 0 => "negative",
        _ => "other",
    }
}

pub fn count_to(n: u32) -> u32 {
    let mut total = 0;
    for i in 0..n {
        total += i;
    }
    let mut k = 0;
    while k < n {
        k += 1;
    }
    loop {
        if k > 100 {
            break;
        }
        k += 1;
    }
    total
}
