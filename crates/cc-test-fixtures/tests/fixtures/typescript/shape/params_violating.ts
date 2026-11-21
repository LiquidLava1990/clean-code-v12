// Sample violating cc.shape.param_count: 7 positional parameters.

export function buildRequest(
  host: string,
  port: number,
  path: string,
  method: string,
  headers: Record<string, string>,
  body: string,
  timeout: number,
): object {
  return { host, port, path, method, headers, body, timeout };
}
