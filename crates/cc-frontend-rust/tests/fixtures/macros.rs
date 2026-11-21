pub fn shout(msg: &str) {
    println!("{}", msg);
    eprintln!("err: {}", msg);
    let v = vec![1, 2, 3];
    assert_eq!(v.len(), 3);
}
