function logged(target: unknown): void {
    void target;
}

@logged
export class Service {
    run(): void {
        return;
    }
}
