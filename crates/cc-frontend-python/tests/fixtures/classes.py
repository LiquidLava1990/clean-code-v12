class Greeter:
    def __init__(self, name: str) -> None:
        self.name = name

    def greet(self) -> str:
        return f"hi, {self.name}"

    def shout(self) -> str:
        return self.greet().upper()
