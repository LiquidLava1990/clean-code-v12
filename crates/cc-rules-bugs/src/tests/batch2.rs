//! Batch 2 probe tests: `callout_under_lock`, `one_ticket_per_refusal`,
//! `unbounded_detail_text`.

use super::{push_file, Fixture};
use crate::BuiltinBugsPack;
use cc_rules::{Rule, RuleRegistry};

fn batch2_findings(rule_id: &str, path: &str, source: &[u8]) -> Vec<cc_finding::Finding> {
    let mut registry = RuleRegistry::new();
    registry.register_pack(&BuiltinBugsPack).unwrap();
    let mut fixture = Fixture::new().with_source(path, source.to_vec());
    push_file(&mut fixture.batch, path);
    registry
        .rule_by_id(rule_id)
        .map_or_else(Vec::new, |rule| rule.run(&fixture.ctx()))
}

#[test]
fn callout_under_lock_reports_external_calls() {
    let source = br#"import threading as threads
from threading import RLock as Reentrant
process_gate = threads.Lock()
class Worker:
    def __init__(self, output: Callable):
        self._dispatch = output
        self.gate = Reentrant()
    def run(self, on_ready=None):
        with self.gate as held:
            self._dispatch()
            on_ready()
        with (other, self.mutex):
            self.bus.publish()
            self.notify_ready()
        with process_gate:
            transport.send()
        gate = threads.Lock()
        with gate:
            self.reporter.file()
"#;
    let findings = batch2_findings("cc.bug.callout_under_lock", "app/worker.py", source);
    assert_eq!(
        findings
            .iter()
            .map(|hit| hit.location.start.line)
            .collect::<Vec<_>>(),
        [10, 11, 13, 14, 16, 19]
    );
    assert!(findings
        .iter()
        .all(|hit| hit.severity == cc_finding::Severity::Required));
}

#[test]
fn callout_under_lock_skips_own_helpers_lock_methods_and_deferred_calls() {
    let source = br#"class Worker:
    def _emit(self):
        pass
    def run(self, handler):
        with self.guard:
            self._emit()
            self.guard.notify()
            self.guard.acquire()
            def later():
                handler()
            job = lambda: handler()
        handler()
        with other:
            service.publish()
def emit():
    pass
with lock:
    emit()
"#;
    assert!(batch2_findings("cc.bug.callout_under_lock", "app/worker.py", source).is_empty());
}

#[test]
fn callout_under_lock_tracks_attribute_bindings_and_injected_tuple_slots() {
    let source = br#"from threading import Lock
class Worker:
    global_gate = Lock()
    def __init__(self, output):
        self._port, self._count = output, 0
        self.callback = self._refresh
    def _refresh(self):
        pass
    def run(self, state):
        state.gate = Lock()
        with state.gate:
            self._port()
            self.callback()
        with self.global_gate:
            service.handle()
"#;
    let findings = batch2_findings("cc.bug.callout_under_lock", "app/worker.py", source);
    assert_eq!(
        findings
            .iter()
            .map(|hit| hit.location.start.line)
            .collect::<Vec<_>>(),
        [12, 15]
    );
}

#[test]
fn callout_under_lock_follows_a_private_helper_to_an_injected_receiver() {
    let source = br#"import threading
class Settings:
    def __init__(self, book):
        self._book = book
        self._lock, self._save_lock = threading.Lock(), threading.Lock()
    def change(self, choices):
        with self._save_lock:
            with self._lock:
                choices = dict(choices)
            self._save(choices)
    def release(self, choices):
        self._save(choices)
    def _save(self, choices):
        if self._book is not None:
            self._book.save(choices)
        self._deeper(choices)
    def _deeper(self, choices):
        self._book.save(choices)
    def direct(self, choices):
        with self._save_lock:
            self._book.save(choices)
"#;
    let findings = batch2_findings("cc.bug.callout_under_lock", "app/settings.py", source);
    assert_eq!(
        findings
            .iter()
            .map(|hit| hit.location.start.line)
            .collect::<Vec<_>>(),
        [15, 21]
    );
}

#[test]
fn callout_under_lock_tracks_explicit_acquire_and_matching_release() {
    let source = br#"class Gate:
    def straight(self):
        self._write_lock.acquire()
        other_lock.release()
        self.transport.send()
        self._write_lock.release()
        self.transport.send()
    def guarded(self):
        self._write_lock.acquire()
        try:
            self.transport.send()
        finally:
            self.transport.notify()
            self._write_lock.release()
            self.transport.send()
        self.transport.send()
    def flush(self):
        self._write_lock.acquire()
        self._flush_held()
        self.transport.send()
    def try_flush(self):
        if self._write_lock.acquire(timeout=0):
            self._flush_held()
    def _flush_held(self):
        try:
            self.transport.send()
        finally:
            self._write_lock.release()
        self.transport.send()
    def no_match(self):
        self._write_lock.acquire()
        self.transport.send()
        other_lock.release()
"#;
    let findings = batch2_findings("cc.bug.callout_under_lock", "app/gate.py", source);
    assert_eq!(
        findings
            .iter()
            .map(|hit| hit.location.start.line)
            .collect::<Vec<_>>(),
        [5, 11, 13, 26]
    );
}

#[test]
fn one_ticket_per_refusal_reports_unguarded_filing_and_downgrades_tests() {
    let source = br#"def act(verdict, sink):
    try:
        run()
    except OSError:
        sink.fault("WRITE", "failed")
    if verdict.allowed:
        proceed()
    else:
        sink.file("GUARD", "place", "denied")
    if not verdict.refused:
        proceed()
    else:
        report_fault("GUARD", "denied")
    if verdict.allowed:
        proceed()
    elif verdict.pending:
        wait()
    else:
        ticket("GUARD", "place")
"#;
    for (path, severity) in [
        ("app/worker.py", cc_finding::Severity::Required),
        ("app/test_worker.py", cc_finding::Severity::Nit),
    ] {
        let findings = batch2_findings("cc.bug.one_ticket_per_refusal", path, source);
        assert_eq!(
            findings
                .iter()
                .map(|hit| hit.location.start.line)
                .collect::<Vec<_>>(),
            [5, 9, 13, 19]
        );
        assert!(findings.iter().all(|hit| hit.severity == severity));
    }
}

#[test]
fn one_ticket_per_refusal_accepts_prior_dedupe_checks() {
    let source = br#"def act(sink, code, place, seen):
    try:
        run()
    except OSError:
        key = code, place
        if key in seen:
            return
        seen.add(key)
        sink.file(code, place, "failed")
def fork(sink, key, cache):
    try:
        run()
    except OSError:
        if key not in cache:
            cache.add(key)
            file_fault(key)
def write(sink, allowed, already_filed):
    if allowed:
        proceed()
    else:
        if not already_filed:
            sink.fault("WRITE", "failed")
"#;
    assert!(batch2_findings("cc.bug.one_ticket_per_refusal", "app/worker.py", source).is_empty());
}

#[test]
fn one_ticket_per_refusal_limits_scope_and_requires_a_real_guard() {
    let source = br#"def act(sink, ready, key):
    if ready:
        proceed()
    else:
        sink.file("NORMAL", "where", "not a refusal")
    try:
        run()
    except OSError:
        def later():
            sink.fault("DEFERRED", "not an exception handler")
        def unrelated(tickets):
            if key in tickets:
                return
        if key not in "abc":
            sink.report_fault("WRITE", "failed")
        if already_filed:
            return
"#;
    let findings = batch2_findings("cc.bug.one_ticket_per_refusal", "app/worker.py", source);
    assert_eq!(
        findings
            .iter()
            .map(|hit| hit.location.start.line)
            .collect::<Vec<_>>(),
        [15]
    );
}

#[test]
fn one_ticket_per_refusal_checks_membership_writes_and_private_guards() {
    let source = br#"class Worker:
    def remember(self, key):
        self._seen.setdefault(key, True)
    def run(self, sink, k):
        recorded = {}
        pending = []
        try:
            work()
        except OSError:
            if k in ALLOWED:
                sink.fault("ALLOWED", "failed")
            if k in READ_ONLY_TICKETS:
                sink.fault("FILTER", "failed")
            if k not in self._seen:
                sink.fault("SEEN", "failed")
            if k not in recorded:
                recorded[k] = True
                sink.fault("RECORDED", "failed")
            if k not in pending:
                pending.append(k)
                sink.fault("PENDING", "failed")
            if self._is_new(k):
                sink.fault("NEW", "failed")
            if self._first_failure(k):
                sink.fault("FIRST", "failed")
            if not self._already_seen(k):
                sink.fault("UNSEEN", "failed")
            if self._renew(k):
                sink.fault("RENEW", "failed")
"#;
    let findings = batch2_findings("cc.bug.one_ticket_per_refusal", "app/worker.py", source);
    assert_eq!(
        findings
            .iter()
            .map(|hit| hit.location.start.line)
            .collect::<Vec<_>>(),
        [11, 13, 29]
    );
}

#[test]
fn unbounded_detail_text_reports_converted_errors_and_payloads() {
    let source = br#"from dataclasses import dataclass
@dataclass
class Notice:
    code: str
    what: str
    description: str = ""
def publish(code, message):
    pass
def record(value, payload, exc, error, sink):
    sink(detail=str(value))
    record = {"why": repr(payload)}
    sink.todo = format(exc)
    try:
        run()
    except OSError as failure:
        sink.message = f"{failure}"
        notice = Notice("WRITE", f"{failure!r}")
        raw = str(failure)
        publish("WRITE", "could not write: " + raw)
        record["reason"] = format((failure))
        sink(reason=f"{error!r}")
        notice = Notice("WRITE", "failed", description=repr(failure))
        key = "why"
        record[key] = str(failure)
"#;
    let findings = batch2_findings("cc.bug.unbounded_detail_text", "app/worker.py", source);
    assert_eq!(
        findings
            .iter()
            .map(|hit| hit.location.start.line)
            .collect::<Vec<_>>(),
        [10, 11, 12, 16, 17, 19, 20, 21, 24]
    );
    assert!(findings
        .iter()
        .all(|hit| hit.severity == cc_finding::Severity::Required));
}

#[test]
fn unbounded_detail_text_accepts_bounding_and_ignores_unrelated_text() {
    let source = br#"def record(payload, sink, ordinary):
    sink(detail=plain_text(payload, LIMIT))
    sink(detail=clip(str(payload)))
    sink(detail=formatter.shorten(f"{payload!r}"))
    sink(detail=(repr(payload))[:LIMIT])
    sink(detail=wrapper((f"{payload}")[:128]))
    sink(detail=f"error: {truncate(format(payload))}")
    sink(detail=str(ordinary))
    sink(result=repr(payload))
    sink(detail=len(str(payload)))
    sink(detail="present" if str(payload) else "empty")
    raw = str(payload)
    sink(detail=bound_detail(raw))
    payload = "a safe string"
    sink(detail=str(payload))
def unrelated(sink):
    value = "constant"
    sink(detail=str(value))
def other(error, str):
    send(detail=str(error))
try:
    run()
except OSError as failure:
    log(str(failure))
else:
    sink(detail=f"{failure}")
"#;
    assert!(batch2_findings("cc.bug.unbounded_detail_text", "app/worker.py", source).is_empty());
}

#[test]
fn unbounded_detail_text_tracks_exception_args_and_whole_bounding_names() {
    let source = br#"from reporting import plain_text as pt
import reporting as reports
def record(sink):
    try:
        run()
    except ValueError as e:
        sink(detail=f"{e.args}")
        sink(detail=inbound(str(e)))
        sink(detail=reports.plain_textual(str(e)))
        sink(detail=pt(str(e), 100))
        sink(detail=reports.clip_detail(str(e)))
        sink(detail=bounded(f"{e.args}"))
        sink(detail=f"{e.code}")
"#;
    let findings = batch2_findings("cc.bug.unbounded_detail_text", "app/worker.py", source);
    assert_eq!(
        findings
            .iter()
            .map(|hit| hit.location.start.line)
            .collect::<Vec<_>>(),
        [7, 8, 9]
    );
}

#[test]
fn unbounded_detail_text_requires_a_real_slice_bound() {
    let source = br#"def record(payload, sink):
    sink(detail=str(payload)[:])
    sink(detail=repr(payload)[::-1])
    sink(detail=clip(str(payload)) + f"{payload}")
    sink(detail=f"{payload}"[:self.limit])
    sink(detail=f"{payload}"[:None])
"#;
    let findings = batch2_findings("cc.bug.unbounded_detail_text", "app/worker.py", source);
    assert_eq!(
        findings
            .iter()
            .map(|hit| hit.location.start.line)
            .collect::<Vec<_>>(),
        [2, 3, 4, 6]
    );
}

#[test]
fn unbounded_detail_text_ignores_other_sink_names() {
    let source = br#"from dataclasses import dataclass
@dataclass
class Issue:
    text: str
@dataclass
class Audit:
    issues: tuple[Issue, ...]
def audit():
    try:
        read()
    except OSError as error:
        self.cause = str(error)
        record = {"code": str(error)}
        record["code"] = str(error)
        sink(code=str(error))
        return Audit((Issue(f"unreadable: {error}"),))
"#;
    let findings = batch2_findings("cc.bug.unbounded_detail_text", "app/audit.py", source);
    assert!(findings.is_empty(), "{findings:?}");
}

#[test]
fn unbounded_detail_text_resolves_imported_signatures_and_typed_receivers() {
    let use_site = br#"from .reporting import Reporter, fail as refusal
class Holder:
    reporter: Reporter
class Worker:
    def __init__(self, reporter: Reporter):
        self.forwarded = reporter
    def run(self, holder: Holder):
        try:
            read()
        except OSError as err:
            self.forwarded.fault("READ", str(err))
            holder.reporter.fault("READ", f"{err!r}")
            raise refusal("READ", repr(err))
"#;
    let declaration = br#"class Reporter:
    def fault(self, code, detail):
        pass
def fail(code, why):
    return ValueError(why)
"#;
    let mut fixture = Fixture::new()
        .with_source("app/worker.py", use_site)
        .with_source("app/reporting.py", declaration);
    push_file(&mut fixture.batch, "app/worker.py");
    let findings = crate::unbounded_detail_text::UnboundedDetailTextRule.run(&fixture.ctx());
    assert_eq!(
        findings
            .iter()
            .map(|hit| hit.location.start.line)
            .collect::<Vec<_>>(),
        [11, 12, 13]
    );
}

#[test]
fn one_ticket_per_refusal_accepts_verified_dedupe_in_imported_sink() {
    let use_site = br#"from app.reporting import Dedupe, Raw, Filtered
class Worker:
    def __init__(self, shared: Dedupe):
        self.created = Dedupe()
        self.forwarded, self.raw = shared, Raw()
        self.filtered = Filtered()
    def run(self):
        try:
            read()
        except OSError:
            self.created.file("READ", "home", "failed")
            self.forwarded.file("READ", "home", "failed")
            self.raw.file("READ", "home", "failed")
            self.filtered.file("READ", "home", "failed")
"#;
    let declaration = br#"class Dedupe:
    def __init__(self):
        self._lock = Lock()
        self._open = {}
    def file(self, code, place, detail):
        with self._lock:
            codes = self._open.setdefault(place, set())
            if code in codes:
                return
            codes.add(code)
        sink.fault(code, detail)
class Raw:
    def file(self, code, place, detail):
        seen = set()
        if (code, place) in seen:
            return
        sink.fault(code, detail)
class Filtered:
    def file(self, code, place, detail):
        if code in self.disabled:
            return
        sink.fault(code, detail)
"#;
    let mut fixture = Fixture::new()
        .with_source("app/worker.py", use_site)
        .with_source("app/reporting.py", declaration);
    push_file(&mut fixture.batch, "app/worker.py");
    let findings = crate::one_ticket_per_refusal::OneTicketPerRefusalRule.run(&fixture.ctx());
    assert_eq!(
        findings
            .iter()
            .map(|hit| hit.location.start.line)
            .collect::<Vec<_>>(),
        [13, 14]
    );
}

#[test]
fn one_ticket_per_refusal_leaves_a_single_filing_test_and_flags_repetition() {
    let source = br#"def test_one_fault_is_recorded():
    sink = Recorder()
    try:
        raise OSError("test trigger")
    except OSError:
        sink.fault("READ", "failed")
    assert sink.events[0].code == "READ"
def test_faults_can_duplicate():
    sink = Recorder()
    for _ in range(3):
        try:
            raise OSError("test trigger")
        except OSError:
            sink.fault("READ", "failed")
    assert sink.events[0].code == "READ"
"#;
    let findings = batch2_findings(
        "cc.bug.one_ticket_per_refusal",
        "tests/test_worker.py",
        source,
    );
    assert_eq!(
        findings
            .iter()
            .map(|hit| hit.location.start.line)
            .collect::<Vec<_>>(),
        [14]
    );
    assert_eq!(findings[0].severity, cc_finding::Severity::Nit);
}
