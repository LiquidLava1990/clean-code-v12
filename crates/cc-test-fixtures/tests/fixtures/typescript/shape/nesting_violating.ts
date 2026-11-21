// Sample violating cc.shape.nesting_depth: 5 levels deep.

interface Record {
  active?: boolean;
  score?: number;
  region?: string;
  tier?: string;
  id: string;
}

export function classify(records: Record[]): string[] {
  const out: string[] = [];
  for (const r of records) {
    if (r) {
      if (r.active) {
        if ((r.score ?? 0) > 0) {
          if (r.region === "us") {
            if (r.tier === "gold") {
              out.push(r.id);
            }
          }
        }
      }
    }
  }
  return out;
}
