//! Unit tests covering the contract spelled out in
//! the Phase-1 design for `cc-rules`.

use camino::Utf8PathBuf;
use cc_config::{Config, RuleConfig, Severity as ConfigSeverity};
use cc_cpg::CpgWriteBatch;
use cc_finding::{
    ActionableMessage, BigO, Category, CostClaim, Evidence, Finding, FindingBuilder, Location,
    Position, ProbeVersion, Remediation, Severity,
};

use crate::{
    run_rule, BuiltinPack, InMemorySourceTable, KernelMeta, ProjectFingerprint, RegistryError,
    Rule, RuleContext, RulePack, RuleRegistry, KERNEL_API_VERSION,
};

// ---------- shared test fixtures -----------------------------------------

fn dummy_location() -> Location {
    Location {
        file: Utf8PathBuf::from("test.rs"),
        start: Position::new(1, 1, 0),
        end: Position::new(1, 1, 0),
        node_id: None,
        function_qualified_name: None,
    }
}

fn dummy_message() -> ActionableMessage {
    ActionableMessage::new(
        "headline",
        "explanation that names what is wrong",
        Remediation::SuggestedRewrite("apply this fix".into()),
    )
}

const fn dummy_cost() -> CostClaim {
    CostClaim::Asymptotic {
        order: BigO::O1,
        param: std::borrow::Cow::Borrowed("test"),
        scenario: std::borrow::Cow::Borrowed("test fixture"),
    }
}

fn dummy_finding(severity: Severity, confidence: f32) -> Finding {
    FindingBuilder::new()
        .rule_id("test.rule")
        .category(Category::Shape)
        .location(dummy_location())
        .message(dummy_message())
        .evidence(Evidence::from_snippet("snippet"))
        .severity(severity)
        .confidence(confidence)
        .cost(dummy_cost())
        .probe_version(ProbeVersion::new("test-pack", "0.1.0", 1, None))
        .build()
        .expect("dummy finding fixture builds")
}

fn make_ctx<'a>(
    batch: &'a CpgWriteBatch,
    source: &'a InMemorySourceTable,
    config: &'a RuleConfig,
    project: &'a ProjectFingerprint,
    kernel: &'a KernelMeta,
) -> RuleContext<'a> {
    RuleContext {
        batch,
        source,
        config,
        project,
        kernel,
    }
}

// ---------- helper rules --------------------------------------------------

struct EmittingRule {
    rule_id: &'static str,
    severity: Severity,
    confidence: f32,
}

impl Rule for EmittingRule {
    fn rule_id(&self) -> &'static str {
        self.rule_id
    }
    fn category(&self) -> Category {
        Category::Shape
    }
    fn default_severity(&self) -> Severity {
        self.severity
    }
    fn default_confidence(&self) -> cc_finding::Confidence {
        cc_finding::Confidence::new(self.confidence)
    }
    fn description(&self) -> &'static str {
        "emits one finding for testing"
    }
    fn run(&self, _ctx: &RuleContext<'_>) -> Vec<Finding> {
        vec![dummy_finding(self.severity, self.confidence)]
    }
}

struct PanickyRule;

impl Rule for PanickyRule {
    fn rule_id(&self) -> &'static str {
        "test.panic"
    }
    fn category(&self) -> Category {
        Category::Shape
    }
    fn default_severity(&self) -> Severity {
        Severity::Required
    }
    fn default_confidence(&self) -> cc_finding::Confidence {
        cc_finding::Confidence::certain()
    }
    fn description(&self) -> &'static str {
        "panics during run for testing"
    }
    fn run(&self, _ctx: &RuleContext<'_>) -> Vec<Finding> {
        panic!("intentional panic for runner test");
    }
}

struct FixedRule {
    rule_id: &'static str,
    severity: Severity,
}

impl Rule for FixedRule {
    fn rule_id(&self) -> &'static str {
        self.rule_id
    }
    fn category(&self) -> Category {
        Category::Shape
    }
    fn default_severity(&self) -> Severity {
        self.severity
    }
    fn default_confidence(&self) -> cc_finding::Confidence {
        cc_finding::Confidence::certain()
    }
    fn description(&self) -> &'static str {
        "no-op rule"
    }
    fn run(&self, _ctx: &RuleContext<'_>) -> Vec<Finding> {
        Vec::new()
    }
}

// ---------- helper packs --------------------------------------------------

struct StaticPack {
    pack_id: &'static str,
    pack_semver: &'static str,
    api_min: u32,
    api_max: Option<u32>,
    rules: &'static [&'static dyn Rule],
}

impl RulePack for StaticPack {
    fn pack_id(&self) -> &'static str {
        self.pack_id
    }
    fn pack_semver(&self) -> &'static str {
        self.pack_semver
    }
    fn kernel_api_min(&self) -> u32 {
        self.api_min
    }
    fn kernel_api_max(&self) -> Option<u32> {
        self.api_max
    }
    fn rules(&self) -> &[&'static dyn Rule] {
        self.rules
    }
}

// ---------- tests ---------------------------------------------------------

#[test]
fn register_unknown_pack_id_works() {
    let mut reg = RuleRegistry::new();
    reg.register_pack(&BuiltinPack)
        .expect("BuiltinPack registers cleanly");
    assert_eq!(reg.rules().count(), 0);
}

#[test]
fn register_rejects_future_kernel_api() {
    static EMPTY: &[&'static dyn Rule] = &[];
    let pack = StaticPack {
        pack_id: "from-the-future",
        pack_semver: "9.9.9",
        api_min: 99,
        api_max: None,
        rules: EMPTY,
    };
    let mut reg = RuleRegistry::new();
    let err = reg.register_pack(&pack).expect_err("future API rejected");
    match err {
        RegistryError::KernelApiTooNew {
            pack_id,
            required,
            available,
        } => {
            assert_eq!(pack_id, "from-the-future");
            assert_eq!(required, 99);
            assert_eq!(available, KERNEL_API_VERSION);
            let msg = err.to_string();
            assert!(msg.contains("upgrade cc-kernel"), "actionable: {msg}");
        }
        other => panic!("unexpected variant: {other:?}"),
    }
}

#[test]
fn panic_in_rule_yields_meta_finding() {
    static PANICKY: &PanickyRule = &PanickyRule;
    let rule: &dyn Rule = PANICKY;

    let batch = CpgWriteBatch::new();
    let source = InMemorySourceTable::new();
    let cfg = RuleConfig::default();
    let project = ProjectFingerprint::empty();
    let kernel = KernelMeta::now();
    let ctx = make_ctx(&batch, &source, &cfg, &project, &kernel);

    let findings = run_rule(rule, "test-pack", &ctx);
    assert_eq!(findings.len(), 1);
    let f = &findings[0];
    assert_eq!(f.category, Category::Meta);
    assert_eq!(f.severity, Severity::Blocker);
    assert!(f.message.headline.contains("test.panic"));
    assert!(f
        .message
        .explanation
        .contains("intentional panic for runner test"));
}

#[test]
fn confidence_threshold_drops_low_confidence_blockers() {
    static RULE: &EmittingRule = &EmittingRule {
        rule_id: "test.low_conf_blocker",
        severity: Severity::Blocker,
        confidence: 0.5,
    };
    let rule: &dyn Rule = RULE;

    let batch = CpgWriteBatch::new();
    let source = InMemorySourceTable::new();
    let cfg = RuleConfig::default();
    let project = ProjectFingerprint::empty();
    let kernel = KernelMeta::now();
    let ctx = make_ctx(&batch, &source, &cfg, &project, &kernel);

    let findings = run_rule(rule, "test-pack", &ctx);
    assert!(
        findings.is_empty(),
        "Blocker @ 0.5 must be dropped (threshold 0.98)"
    );
}

#[test]
fn confidence_threshold_keeps_high_confidence_nit() {
    static RULE: &EmittingRule = &EmittingRule {
        rule_id: "test.high_conf_nit",
        severity: Severity::Nit,
        confidence: 0.7,
    };
    let rule: &dyn Rule = RULE;

    let batch = CpgWriteBatch::new();
    let source = InMemorySourceTable::new();
    let cfg = RuleConfig::default();
    let project = ProjectFingerprint::empty();
    let kernel = KernelMeta::now();
    let ctx = make_ctx(&batch, &source, &cfg, &project, &kernel);

    let findings = run_rule(rule, "test-pack", &ctx);
    assert_eq!(findings.len(), 1, "Nit @ 0.7 must pass (threshold 0.6)");
}

#[test]
fn rule_by_id_returns_registered() {
    static RULE: &FixedRule = &FixedRule {
        rule_id: "test.lookup",
        severity: Severity::Required,
    };
    static RULES: &[&'static dyn Rule] = &[RULE];
    let pack = StaticPack {
        pack_id: "lookup-pack",
        pack_semver: "0.1.0",
        api_min: 1,
        api_max: None,
        rules: RULES,
    };

    let mut reg = RuleRegistry::new();
    reg.register_pack(&pack).expect("registers");
    let found = reg.rule_by_id("test.lookup").expect("lookup hits");
    assert_eq!(found.rule_id(), "test.lookup");
    assert!(reg.rule_by_id("nope").is_none());
}

#[test]
fn apply_config_combines_overrides() {
    static RULE: &FixedRule = &FixedRule {
        rule_id: "test.override",
        severity: Severity::Required,
    };
    static RULES: &[&'static dyn Rule] = &[RULE];
    let pack = StaticPack {
        pack_id: "override-pack",
        pack_semver: "0.1.0",
        api_min: 1,
        api_max: None,
        rules: RULES,
    };
    let mut reg = RuleRegistry::new();
    reg.register_pack(&pack).expect("registers");

    let mut cfg = Config::default();
    cfg.rules.insert(
        "test.override".into(),
        RuleConfig {
            severity_override: Some(ConfigSeverity::Nit),
            ..RuleConfig::default()
        },
    );

    let effective = reg.apply_config(&cfg);
    assert_eq!(effective.len(), 1);
    assert_eq!(effective[0].severity, Severity::Nit);
    assert!(effective[0].enabled);
}

#[test]
fn effective_rule_carries_provenance() {
    static RULE: &FixedRule = &FixedRule {
        rule_id: "test.prov",
        severity: Severity::Required,
    };
    static RULES: &[&'static dyn Rule] = &[RULE];
    let pack = StaticPack {
        pack_id: "prov-pack",
        pack_semver: "1.2.3",
        api_min: 1,
        api_max: None,
        rules: RULES,
    };
    let mut reg = RuleRegistry::new();
    reg.register_pack(&pack).expect("registers");

    let cfg = Config::default();
    let effective = reg.apply_config(&cfg);
    assert_eq!(effective.len(), 1);
    assert_eq!(effective[0].pack_id, "prov-pack");
    assert_eq!(effective[0].pack_semver, "1.2.3");
    assert_eq!(effective[0].rule_id(), "test.prov");
    let owner = reg.pack_of("test.prov").expect("pack_of resolves");
    assert_eq!(owner, ("prov-pack", "1.2.3"));
}
