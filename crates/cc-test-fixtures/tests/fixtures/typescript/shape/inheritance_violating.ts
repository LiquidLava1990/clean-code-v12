// Sample violating cc.shape.no_inheritance: class extends class.

export class Worker {
  constructor(public readonly name: string) {}

  announce(): string {
    return `worker:${this.name}`;
  }
}

export class Manager extends Worker {
  constructor(name: string, public readonly reports: string[]) {
    super(name);
  }

  override announce(): string {
    return `manager:${this.name}:${this.reports.length}`;
  }
}
