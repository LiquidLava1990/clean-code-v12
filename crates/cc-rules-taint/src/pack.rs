//! [`BuiltinTaintPack`] — registers the fifteen Family-4 probes.

use cc_rules::{Rule, RulePack, KERNEL_API_VERSION};

use crate::command_injection::CommandInjectionRule;
use crate::eval_dynamic_code::EvalDynamicCodeRule;
use crate::gosec_command_injection_exec::GosecCommandInjectionExecRule;
use crate::gosec_filepath_traversal::GosecFilepathTraversalRule;
use crate::gosec_sql_concat::GosecSqlConcatRule;
use crate::gosec_template_html_unescaped::GosecTemplateHtmlUnescapedRule;
use crate::gosec_unsafe_pointer_use::GosecUnsafePointerUseRule;
use crate::path_traversal::PathTraversalRule;
use crate::path_traversal_join::PathTraversalJoinRule;
use crate::repr_on_untrusted::ReprOnUntrustedRule;
use crate::sql_injection::SqlInjectionRule;
use crate::ssrf::SsrfRule;
use crate::unsafe_deserialization::UnsafeDeserializationRule;
use crate::weak_password_hash::WeakPasswordHashRule;
use crate::xss::XssRule;

/// Built-in Family-4 [`RulePack`] — fifteen probes registered at boot.
#[derive(Debug, Default, Clone, Copy)]
pub struct BuiltinTaintPack;

impl BuiltinTaintPack {
    /// Stable pack id. Distinct from sibling Phase-2 packs so the registry
    /// can host every pack side-by-side without collision.
    pub const PACK_ID: &'static str = "cc-builtin-taint";

    /// Pack semver — pinned to the crate version.
    pub const PACK_SEMVER: &'static str = env!("CARGO_PKG_VERSION");
}

static SQL_INJECTION: SqlInjectionRule = SqlInjectionRule;
static XSS: XssRule = XssRule;
static COMMAND_INJECTION: CommandInjectionRule = CommandInjectionRule;
static UNSAFE_DESERIALIZATION: UnsafeDeserializationRule = UnsafeDeserializationRule;
static PATH_TRAVERSAL: PathTraversalRule = PathTraversalRule;
static REPR_ON_UNTRUSTED: ReprOnUntrustedRule = ReprOnUntrustedRule;
static SSRF: SsrfRule = SsrfRule;
// Phase 10 probes (Batch L — cross-cutting, multi-language).
static WEAK_PASSWORD_HASH: WeakPasswordHashRule = WeakPasswordHashRule;
static PATH_TRAVERSAL_JOIN: PathTraversalJoinRule = PathTraversalJoinRule;
static EVAL_DYNAMIC_CODE: EvalDynamicCodeRule = EvalDynamicCodeRule;
// Phase 10 probes (Go gosec).
static GOSEC_SQL_CONCAT: GosecSqlConcatRule = GosecSqlConcatRule;
static GOSEC_COMMAND_INJECTION_EXEC: GosecCommandInjectionExecRule = GosecCommandInjectionExecRule;
static GOSEC_UNSAFE_POINTER_USE: GosecUnsafePointerUseRule = GosecUnsafePointerUseRule;
static GOSEC_TEMPLATE_HTML_UNESCAPED: GosecTemplateHtmlUnescapedRule =
    GosecTemplateHtmlUnescapedRule;
static GOSEC_FILEPATH_TRAVERSAL: GosecFilepathTraversalRule = GosecFilepathTraversalRule;

static RULES: &[&'static dyn Rule] = &[
    &SQL_INJECTION,
    &XSS,
    &COMMAND_INJECTION,
    &UNSAFE_DESERIALIZATION,
    &PATH_TRAVERSAL,
    &REPR_ON_UNTRUSTED,
    &SSRF,
    &WEAK_PASSWORD_HASH,
    &PATH_TRAVERSAL_JOIN,
    &EVAL_DYNAMIC_CODE,
    &GOSEC_SQL_CONCAT,
    &GOSEC_COMMAND_INJECTION_EXEC,
    &GOSEC_UNSAFE_POINTER_USE,
    &GOSEC_TEMPLATE_HTML_UNESCAPED,
    &GOSEC_FILEPATH_TRAVERSAL,
];

impl RulePack for BuiltinTaintPack {
    fn pack_id(&self) -> &'static str {
        Self::PACK_ID
    }
    fn pack_semver(&self) -> &'static str {
        Self::PACK_SEMVER
    }
    fn kernel_api_min(&self) -> u32 {
        KERNEL_API_VERSION
    }
    fn kernel_api_max(&self) -> Option<u32> {
        None
    }
    fn rules(&self) -> &[&'static dyn Rule] {
        RULES
    }
}
