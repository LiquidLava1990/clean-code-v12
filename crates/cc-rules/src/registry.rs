//! [`RuleRegistry`] — registration + lookup of [`RulePack`]s and rules.
//!
//! The registry is the single source of truth for "what rules exist
//! in this kernel run". Packs register; the kernel iterates. Pack
//! provenance is preserved so diagnostics can name the originating
//! pack ("rule `cc.shape.fn_length` comes from pack `cc-builtin@0.1.0`").

use std::collections::{BTreeMap, BTreeSet};

use cc_config::Config;

use crate::effective::EffectiveRule;
use crate::error::{RegistryError, RegistryResult};
use crate::rule::{Rule, RulePack, KERNEL_API_VERSION};

/// Registered pack — keeps rules + provenance together.
///
/// Rules are stored as an owned `Vec` of `'static` trait-object refs;
/// each reference points into the pack's static rule table, but the
/// outer slice is allocated in the registry so we are not bound by the
/// pack reference's lifetime.
struct PackEntry {
    pack_id: &'static str,
    pack_semver: &'static str,
    rules: Vec<&'static dyn Rule>,
}

/// Central registry for [`RulePack`]s + rules.
///
/// Stage-1 implementation: in-memory `BTreeMap`s. Stage-2 (when
/// dynamic pack loading lands) will swap the storage for a layered
/// resolver that respects pack-priority.
#[derive(Default)]
pub struct RuleRegistry {
    packs: Vec<PackEntry>,
    rule_by_id: BTreeMap<&'static str, usize>,
    pack_ids: BTreeSet<&'static str>,
}

impl RuleRegistry {
    /// Build an empty registry.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a pack.
    ///
    /// # Errors
    ///
    /// - [`RegistryError::KernelApiTooNew`] when the pack's
    ///   `kernel_api_min` is greater than [`KERNEL_API_VERSION`].
    /// - [`RegistryError::KernelApiTooOld`] when the pack's
    ///   `kernel_api_max` is less than [`KERNEL_API_VERSION`].
    /// - [`RegistryError::DuplicatePackId`] when a pack with the same
    ///   `pack_id` is already registered.
    /// - [`RegistryError::DuplicateRuleId`] when any rule the pack
    ///   contributes shares an id with an already-registered rule.
    pub fn register_pack(&mut self, pack: &dyn RulePack) -> RegistryResult<()> {
        let pack_id = pack.pack_id();
        Self::check_api_window(pack)?;
        self.check_pack_unique(pack_id)?;
        self.check_rules_unique(pack_id, pack.rules())?;
        self.commit_pack(pack);
        Ok(())
    }

    /// Iterate every registered rule across all packs. Order matches
    /// registration order across packs, then per-pack rule order.
    pub fn rules(&self) -> impl Iterator<Item = &'static dyn Rule> + '_ {
        self.packs
            .iter()
            .flat_map(|entry| entry.rules.iter().copied())
    }

    /// Look up a rule by its stable id.
    #[must_use]
    pub fn rule_by_id(&self, rule_id: &str) -> Option<&'static dyn Rule> {
        let pack_idx = *self.rule_by_id.get(rule_id)?;
        self.packs[pack_idx]
            .rules
            .iter()
            .copied()
            .find(|rule| rule.rule_id() == rule_id)
    }

    /// Find the pack that owns the given rule id, if any.
    #[must_use]
    pub fn pack_of(&self, rule_id: &str) -> Option<(&'static str, &'static str)> {
        let pack_idx = *self.rule_by_id.get(rule_id)?;
        let entry = &self.packs[pack_idx];
        Some((entry.pack_id, entry.pack_semver))
    }

    /// Combine rule defaults + per-rule config into a runnable list.
    ///
    /// Tier-0 enable-disable invariants are validated upstream by
    /// `cc-config::validate`; this method trusts them and merely
    /// translates the resolved values into [`EffectiveRule`]s.
    ///
    /// Disabled rules are still returned (with `enabled = false`) so
    /// the kernel can report "rule X is disabled by config" diagnostics
    /// rather than silently dropping them.
    #[must_use]
    pub fn apply_config(&self, config: &Config) -> Vec<EffectiveRule> {
        let mut effective = Vec::with_capacity(self.rule_by_id.len());
        for entry in &self.packs {
            for &rule in &entry.rules {
                effective.push(EffectiveRule::resolve(
                    rule,
                    entry.pack_id,
                    entry.pack_semver,
                    config,
                ));
            }
        }
        effective
    }

    fn check_api_window(pack: &dyn RulePack) -> RegistryResult<()> {
        if pack.kernel_api_min() > KERNEL_API_VERSION {
            return Err(RegistryError::KernelApiTooNew {
                pack_id: pack.pack_id(),
                required: pack.kernel_api_min(),
                available: KERNEL_API_VERSION,
            });
        }
        if let Some(cap) = pack.kernel_api_max() {
            if cap < KERNEL_API_VERSION {
                return Err(RegistryError::KernelApiTooOld {
                    pack_id: pack.pack_id(),
                    cap,
                    available: KERNEL_API_VERSION,
                });
            }
        }
        Ok(())
    }

    fn check_pack_unique(&self, pack_id: &'static str) -> RegistryResult<()> {
        if self.pack_ids.contains(pack_id) {
            return Err(RegistryError::DuplicatePackId { pack_id });
        }
        Ok(())
    }

    fn check_rules_unique(
        &self,
        incoming_pack: &'static str,
        rules: &[&'static dyn Rule],
    ) -> RegistryResult<()> {
        for rule in rules {
            let id = rule.rule_id();
            if let Some(&existing_idx) = self.rule_by_id.get(id) {
                return Err(RegistryError::DuplicateRuleId {
                    rule_id: id,
                    existing_pack: self.packs[existing_idx].pack_id,
                    incoming_pack,
                });
            }
        }
        Ok(())
    }

    fn commit_pack(&mut self, pack: &dyn RulePack) {
        let pack_id = pack.pack_id();
        let entry = PackEntry {
            pack_id,
            pack_semver: pack.pack_semver(),
            rules: pack.rules().to_vec(),
        };
        let idx = self.packs.len();
        for rule in &entry.rules {
            self.rule_by_id.insert(rule.rule_id(), idx);
        }
        self.pack_ids.insert(pack_id);
        self.packs.push(entry);
    }
}

/// A placeholder [`RulePack`] that ships zero rules.
///
/// The real Tier-0 rules live in `cc-rules-tier0`. This pack exists so
/// downstream crates (and unit tests) can register a built-in pack
/// without pulling in the full Tier-0 implementation. Once Tier-0
/// lands, this struct will be replaced by the real built-in pack via
/// re-export from `cc-rules-tier0`.
#[derive(Debug, Default, Clone, Copy)]
pub struct BuiltinPack;

impl BuiltinPack {
    /// Stable pack id used by [`RulePack::pack_id`].
    pub const PACK_ID: &'static str = "cc-builtin";
    /// Pack semver — synced to the `cc-rules` crate version.
    pub const PACK_SEMVER: &'static str = env!("CARGO_PKG_VERSION");
}

impl RulePack for BuiltinPack {
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
        &[]
    }
}
