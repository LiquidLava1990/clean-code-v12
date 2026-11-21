// Sample clean cc.error.bare: typed catch with actionable error.

export class FixtureLoadError extends Error {
  constructor(message: string, options?: { cause: unknown }) {
    super(message, options);
    this.name = "FixtureLoadError";
  }
}

export function safeLoad(loader: () => string): string {
  try {
    return loader();
  } catch (err: unknown) {
    throw new FixtureLoadError(
      `failed to load fixture; verify the loader closure does not throw, ` +
        `then retry. underlying=${typeof err}`,
      { cause: err },
    );
  }
}
