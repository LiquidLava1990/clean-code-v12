<!-- Clean Code V12 PR template -->

## Summary

<!-- What does this PR change and why? Reference the issue or rule id (e.g. R-FN-LEN). -->

## Tier-0 forever-rules verification

- [ ] No new function exceeds 50 LOC
- [ ] No new file exceeds 1500 LOC
- [ ] No nesting > 3 levels introduced
- [ ] No bare `except` / catch-all introduced (`R-ERR-BARE`)
- [ ] All new public signatures fully typed (`R-TYPE`)
- [ ] All error messages include WHAT happened AND HOW to fix (`R-ERR-ACTION`)
- [ ] Touched files cleaner than I found them (`R-REFACTOR`)
- [ ] New files clean from line 1 (`R-CLEAN-1`)
- [ ] `ccv12 check . --severity blocker` reports no new Blocker findings

## Test plan

<!-- How was this verified? RED -> GREEN -> REFACTOR for behavior changes. -->

- [ ] `cargo test --workspace` GREEN
- [ ] `cargo clippy --workspace --all-targets -- -D warnings` GREEN
- [ ] `cargo fmt --all -- --check` GREEN
- [ ] `cargo deny check` GREEN
- [ ] Tier-0 dogfood workflow GREEN

## Notes for reviewer

<!-- Anything non-obvious? Trade-offs considered? Future-work TODOs? -->
