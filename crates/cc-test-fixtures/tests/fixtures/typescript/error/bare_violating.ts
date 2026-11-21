// Sample violating cc.error.bare: catch with no binding swallows errors.

export function safeLoad(loader: () => string): string | null {
  try {
    return loader();
  } catch {
    // Bare catch — no error info captured, no recovery hint.
    return null;
  }
}
