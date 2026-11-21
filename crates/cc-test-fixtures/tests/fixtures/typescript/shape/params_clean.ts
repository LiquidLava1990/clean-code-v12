// Sample clean cc.shape.param_count: parameters bundled into a spec.

export interface RequestSpec {
  host: string;
  port: number;
  path: string;
  method: string;
  headers: Record<string, string>;
  body: string;
  timeout: number;
}

export function buildRequest(spec: RequestSpec): RequestSpec {
  return { ...spec };
}
