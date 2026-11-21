//! Sample clean cc.shape.fn_length: small composed functions.

#[derive(Debug, Clone, Default)]
pub struct Record {
    pub id: String,
    pub status: String,
    pub score: i64,
}

pub fn process_records(records: &[Record]) -> Vec<Record> {
    records
        .iter()
        .filter(|r| !is_rejected(r))
        .cloned()
        .map(enrich)
        .collect()
}

fn is_rejected(record: &Record) -> bool {
    record.status == "rejected"
}

fn enrich(mut record: Record) -> Record {
    record.score /= 100;
    record
}
