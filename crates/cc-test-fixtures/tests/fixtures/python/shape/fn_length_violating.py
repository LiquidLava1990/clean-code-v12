"""Sample violating cc.shape.fn_length: function exceeds 50 logical LOC."""


def process_records(records):
    # Deliberately long function to trigger fn_length rule.
    out = []
    seen = set()
    skipped = 0
    accepted = 0
    rejected = 0
    flagged = 0
    queued = 0
    deferred = 0
    audited = 0
    for r in records:
        if r is None:
            skipped += 1
            continue
        if r.get("id") in seen:
            skipped += 1
            continue
        seen.add(r.get("id"))
        if r.get("status") == "rejected":
            rejected += 1
            continue
        if r.get("status") == "flagged":
            flagged += 1
            out.append({"id": r["id"], "kind": "flag"})
            continue
        if r.get("status") == "queued":
            queued += 1
            out.append({"id": r["id"], "kind": "queue"})
            continue
        if r.get("status") == "deferred":
            deferred += 1
            out.append({"id": r["id"], "kind": "defer"})
            continue
        if r.get("status") == "audit":
            audited += 1
            out.append({"id": r["id"], "kind": "audit"})
            continue
        accepted += 1
        out.append(
            {
                "id": r["id"],
                "kind": "ok",
                "score": r.get("score", 0),
                "tags": r.get("tags", []),
                "owner": r.get("owner"),
                "team": r.get("team"),
                "region": r.get("region"),
            }
        )
    summary = {
        "accepted": accepted,
        "rejected": rejected,
        "flagged": flagged,
        "queued": queued,
        "deferred": deferred,
        "audited": audited,
        "skipped": skipped,
    }
    return out, summary
