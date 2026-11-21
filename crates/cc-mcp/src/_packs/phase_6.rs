//! Phase 6: modernization, test design, supply chain, formatting, IaC.

use cc_rules::RuleRegistry;
use cc_rules_formatting::BuiltinFormattingPack;
use cc_rules_iac::BuiltinIacPack;
use cc_rules_modernize::BuiltinModernizePack;
use cc_rules_supplychain::BuiltinSupplyChainPack;
use cc_rules_test_design::BuiltinTestDesignPack;

use super::pack_err;

pub fn register(registry: &mut RuleRegistry) -> Result<(), String> {
    registry
        .register_pack(&BuiltinModernizePack)
        .map_err(pack_err)?;
    registry
        .register_pack(&BuiltinTestDesignPack)
        .map_err(pack_err)?;
    registry
        .register_pack(&BuiltinSupplyChainPack)
        .map_err(pack_err)?;
    registry
        .register_pack(&BuiltinFormattingPack)
        .map_err(pack_err)?;
    registry.register_pack(&BuiltinIacPack).map_err(pack_err)?;
    Ok(())
}
