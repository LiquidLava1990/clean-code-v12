//! Phase 4: tests, database, anti-fragility, observability, api,
//! deploy, ops, ci, history.

use cc_rules::RuleRegistry;
use cc_rules_anti_fragility::BuiltinAntiFragilityPack;
use cc_rules_api::BuiltinApiPack;
use cc_rules_ci::BuiltinCiPack;
use cc_rules_database::BuiltinDatabasePack;
use cc_rules_deploy::BuiltinDeployPack;
use cc_rules_history::BuiltinHistoryPack;
use cc_rules_observability::BuiltinObservabilityPack;
use cc_rules_ops::BuiltinOpsPack;
use cc_rules_tests::BuiltinTestsPack;

use super::pack_err;

pub fn register(registry: &mut RuleRegistry) -> Result<(), String> {
    registry
        .register_pack(&BuiltinTestsPack)
        .map_err(pack_err)?;
    registry
        .register_pack(&BuiltinDatabasePack)
        .map_err(pack_err)?;
    registry
        .register_pack(&BuiltinAntiFragilityPack)
        .map_err(pack_err)?;
    registry
        .register_pack(&BuiltinObservabilityPack)
        .map_err(pack_err)?;
    registry.register_pack(&BuiltinApiPack).map_err(pack_err)?;
    registry
        .register_pack(&BuiltinDeployPack)
        .map_err(pack_err)?;
    registry.register_pack(&BuiltinOpsPack).map_err(pack_err)?;
    registry.register_pack(&BuiltinCiPack).map_err(pack_err)?;
    registry
        .register_pack(&BuiltinHistoryPack)
        .map_err(pack_err)?;
    Ok(())
}
