"""Sample violating cc.shape.no_inheritance: Manager extends Worker."""


class Worker:
    # Base class with shared behaviour.
    def __init__(self, name):
        self.name = name

    def announce(self):
        return f"worker:{self.name}"


class Manager(Worker):
    # Inheritance — flagged by no_inheritance rule.
    def __init__(self, name, reports):
        super().__init__(name)
        self.reports = reports

    def announce(self):
        return f"manager:{self.name}:{len(self.reports)}"
