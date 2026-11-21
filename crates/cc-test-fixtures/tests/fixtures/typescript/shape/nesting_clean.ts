// Sample clean cc.shape.nesting_depth: early returns keep depth shallow.

interface Record {
  active?: boolean;
  score?: number;
  region?: string;
  tier?: string;
  id: string;
}

export function classify(records: Record[]): string[] {
  return records.filter(isGoldUsActive).map((r) => r.id);
}

function isGoldUsActive(record: Record): boolean {
  if (!record) return false;
  if (!record.active) return false;
  if ((record.score ?? 0) <= 0) return false;
  return record.region === "us" && record.tier === "gold";
}
