pub fn longest<'a, 'b>(x: &'a str, y: &'b str) -> &'a str
where
    'b: 'a,
{
    if x.len() >= y.len() {
        x
    } else {
        x
    }
}
