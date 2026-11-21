// Sample violating cc.shape.fn_length: function exceeds 50 logical LOC.

interface Record {
  id: string;
  status?: string;
  score?: number;
  region?: string;
  tier?: string;
}

export function processRecords(records: Record[]): Record[] {
  const out: Record[] = [];
  const seen = new Set<string>();
  let skipped = 0;
  let accepted = 0;
  let rejected = 0;
  let flagged = 0;
  let queued = 0;
  let deferred = 0;
  let audited = 0;
  for (const r of records) {
    if (!r) {
      skipped += 1;
      continue;
    }
    if (seen.has(r.id)) {
      skipped += 1;
      continue;
    }
    seen.add(r.id);
    if (r.status === "rejected") {
      rejected += 1;
      continue;
    }
    if (r.status === "flagged") {
      flagged += 1;
      out.push({ id: r.id, status: "flag" });
      continue;
    }
    if (r.status === "queued") {
      queued += 1;
      out.push({ id: r.id, status: "queue" });
      continue;
    }
    if (r.status === "deferred") {
      deferred += 1;
      out.push({ id: r.id, status: "defer" });
      continue;
    }
    if (r.status === "audit") {
      audited += 1;
      out.push({ id: r.id, status: "audit" });
      continue;
    }
    accepted += 1;
    out.push({
      id: r.id,
      status: "ok",
      score: r.score ?? 0,
      region: r.region,
      tier: r.tier,
    });
  }
  void skipped;
  void accepted;
  void rejected;
  void flagged;
  void queued;
  void deferred;
  void audited;
  return out;
}
