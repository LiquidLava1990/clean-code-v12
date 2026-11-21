// Sample clean cc.shape.fn_length: small composed functions.

interface Record {
  id: string;
  status?: string;
  score?: number;
}

export function processRecords(records: Record[]): Record[] {
  return records.filter((r) => !isRejected(r)).map(enrich);
}

function isRejected(record: Record): boolean {
  return record.status === "rejected";
}

function enrich(record: Record): Record {
  return { ...record, score: (record.score ?? 0) / 100 };
}
