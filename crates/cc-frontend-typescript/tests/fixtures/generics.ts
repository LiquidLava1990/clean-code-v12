export function identity<T>(x: T): T {
    return x;
}

export function pair<A, B>(a: A, b: B): [A, B] {
    return [a, b];
}
