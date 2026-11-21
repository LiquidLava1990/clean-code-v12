export class Greeter {
    private readonly name: string;

    constructor(name: string) {
        this.name = name;
    }

    greet(): string {
        return `hi, ${this.name}`;
    }

    shout(): string {
        return this.greet().toUpperCase();
    }
}
