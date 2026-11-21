//! Phase 2: slop, secrets, perf, completeness.

use cc_rules::RuleRegistry;
use cc_rules_completeness::BuiltinCompletenessPack;
use cc_rules_perf::BuiltinPerfPack;
use cc_rules_secrets::BuiltinSecretsPack;
use cc_rules_slop::BuiltinSlopPack;

use super::pack_err;

pub fn register(registry: &mut RuleRegistry) -> Result<(), String> {
    registry.register_pack(&BuiltinSlopPack).map_err(pack_err)?;
    registry
        .register_pack(&BuiltinSecretsPack)
        .map_err(pack_err)?;
    registry.register_pack(&BuiltinPerfPack).map_err(pack_err)?;
    registry
        .register_pack(&BuiltinCompletenessPack)
        .map_err(pack_err)?;
    Ok(())
}
