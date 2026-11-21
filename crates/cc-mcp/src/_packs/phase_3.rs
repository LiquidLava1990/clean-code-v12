//! Phase 3: bugs, concurrency, time-math, taint, memory, types,
//! architecture, layout conventions.

use cc_rules::RuleRegistry;
use cc_rules_architecture::BuiltinArchitecturePack;
use cc_rules_bugs::BuiltinBugsPack;
use cc_rules_concurrency::BuiltinConcurrencyPack;
use cc_rules_conventions::BuiltinConventionsPack;
use cc_rules_memory::BuiltinMemoryPack;
use cc_rules_taint::BuiltinTaintPack;
use cc_rules_time_math::BuiltinTimeMathPack;
use cc_rules_types::BuiltinTypesPack;

use super::pack_err;

pub fn register(registry: &mut RuleRegistry) -> Result<(), String> {
    registry.register_pack(&BuiltinBugsPack).map_err(pack_err)?;
    registry
        .register_pack(&BuiltinConcurrencyPack)
        .map_err(pack_err)?;
    registry
        .register_pack(&BuiltinTimeMathPack)
        .map_err(pack_err)?;
    registry
        .register_pack(&BuiltinTaintPack)
        .map_err(pack_err)?;
    registry
        .register_pack(&BuiltinMemoryPack)
        .map_err(pack_err)?;
    registry
        .register_pack(&BuiltinTypesPack)
        .map_err(pack_err)?;
    registry
        .register_pack(&BuiltinArchitecturePack)
        .map_err(pack_err)?;
    registry
        .register_pack(&BuiltinConventionsPack)
        .map_err(pack_err)?;
    Ok(())
}
