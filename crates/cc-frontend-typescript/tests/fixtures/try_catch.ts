export function safeDiv(a: number, b: number): number | null {
    try {
        return a / b;
    } catch (e: unknown) {
        return null;
    } finally {
        return -1;
    }
}
