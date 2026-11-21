pub trait Speak {
    fn name(&self) -> &str;

    fn greet(&self) -> String {
        format!("Hello from {}", self.name())
    }
}

pub struct Dog;

impl Speak for Dog {
    fn name(&self) -> &str {
        "Dog"
    }
}
