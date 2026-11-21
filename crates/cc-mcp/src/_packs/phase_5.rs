//! Phase 5: docs, compliance, i18n + a11y.

use cc_rules::RuleRegistry;
use cc_rules_compliance::BuiltinCompliancePack;
use cc_rules_docs::BuiltinDocsPack;
use cc_rules_i18n_a11y::BuiltinI18nA11yPack;

use super::pack_err;

pub fn register(registry: &mut RuleRegistry) -> Result<(), String> {
    registry.register_pack(&BuiltinDocsPack).map_err(pack_err)?;
    registry
        .register_pack(&BuiltinCompliancePack)
        .map_err(pack_err)?;
    registry
        .register_pack(&BuiltinI18nA11yPack)
        .map_err(pack_err)?;
    Ok(())
}
