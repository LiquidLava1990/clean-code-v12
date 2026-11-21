//! Built-in pack registration helpers.
//!
//! Mirrors `cc_kernel::Kernel::with_default_packs` exactly. Lives in a
//! sub-module so each phase stays under the 30-import god-module
//! threshold — the Kernel itself uses the same per-phase split.

use cc_rules::{RegistryError, RuleRegistry};

mod phase_1;
mod phase_2;
mod phase_3;
mod phase_4;
mod phase_5;
mod phase_6;

/// Register every built-in pack into a fresh [`RuleRegistry`].
///
/// # Errors
///
/// Surfaces the first [`RegistryError`] from any phase as an actionable
/// string for the MCP tool-error envelope.
pub fn register_default_packs(registry: &mut RuleRegistry) -> Result<(), String> {
    phase_1::register(registry)?;
    phase_2::register(registry)?;
    phase_3::register(registry)?;
    phase_4::register(registry)?;
    phase_5::register(registry)?;
    phase_6::register(registry)?;
    Ok(())
}

/// Shared error mapper used by every phase module.
pub(super) fn pack_err(err: RegistryError) -> String {
    format!("pack registration failed: {err}. Fix: ensure no upstream pack registered the same id.",)
}
