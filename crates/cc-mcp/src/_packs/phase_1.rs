//! Phase 1: the Tier-0 forever-rules pack.

use cc_rules::RuleRegistry;
use cc_rules_tier0::BuiltinTier0Pack;

use super::pack_err;

pub fn register(registry: &mut RuleRegistry) -> Result<(), String> {
    registry
        .register_pack(&BuiltinTier0Pack)
        .map_err(pack_err)?;
    Ok(())
}
