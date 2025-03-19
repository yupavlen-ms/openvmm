// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! CPUID definitions and implementation specific to Underhill in hardware CVMs.

#![warn(missing_docs)]

use self::snp::SnpCpuidSupport;
use self::tdx::TdxCpuidInitializer;
use self::tdx::TdxCpuidSupport;
use core::arch::x86_64::CpuidResult;
use masking::CpuidResultMask;
use snp::SnpCpuidInitializer;
use std::boxed::Box;
use std::collections::BTreeMap;
use std::collections::HashMap;
use thiserror::Error;
use x86defs::cpuid;
use x86defs::cpuid::CpuidFunction;
use x86defs::snp::HvPspCpuidPage;
use x86defs::xsave;

mod masking;
mod snp;
mod tdx;
#[cfg(test)]
mod tests;

struct ExtendedTopologyResult {
    subleaf0: Option<CpuidResult>,
    subleaf1: Option<CpuidResult>,
    vps_per_socket: u32,
}

/// Architecture-specific behaviors for initializing cpuid results
trait CpuidArchInitializer {
    /// The value that should be returned when querying cpuid for the vendor
    fn vendor(&self) -> cpuid::Vendor;

    /// Maximum cpuid function
    fn max_function(&self) -> u32;

    /// Maximum extended cpuid function
    fn extended_max_function(&self) -> u32;

    /// The paravisor should only expose CPUID features that are known and
    /// supported. If the given leaf--and if applicable, subleaf--is supported,
    /// provides the mask to filter in the values that are supported and also
    /// indicates whether the result is in fact a subleaf. This will be combined with
    /// the result of the cross-architecture [`CpuidResults::leaf_mask`].
    fn additional_leaf_mask(&self, leaf: CpuidFunction, subleaf: u32) -> Option<CpuidResultMask>;

    /// Validates the parsed results. result is a helper for retrieving the
    /// current result for a given leaf, Some(subleaf) combination.
    fn validate_results(&self, results: &CpuidResults) -> Result<(), CpuidResultsError>;

    /// Returns a vector containing the expected CPUID results that should be cached.
    fn cpuid_info(&self) -> Vec<ParsedCpuidEntry>;

    /// Processes extended state enumeration subleaves 2+. result is a helper
    /// for retrieving the result of a given subleaf.
    //
    // (TODO TDX: This will be to populate them, will need to update the
    // signature to pass CpuidResults as a mutable reference)
    fn process_extended_state_subleaves(
        &self,
        results: &mut CpuidSubtable,
        extended_state_mask: u64,
    ) -> Result<(), CpuidResultsError>;

    /// Computes the Extended Topology results from other leaves if necessary.
    ///
    /// On some platforms, subleafs is already set as part of the initial set
    /// of leaves and no additional update is needed.
    fn extended_topology(
        &self,
        version_and_features_ebx: cpuid::VersionAndFeaturesEbx,
        version_and_features_edx: cpuid::VersionAndFeaturesEdx,
        address_space_sizes_ecx: cpuid::ExtendedAddressSpaceSizesEcx,
        processor_topology_ebx: Option<cpuid::ProcessorTopologyDefinitionEbx>,
    ) -> Result<ExtendedTopologyResult, CpuidResultsError>;

    /// If the value needs to be changed based on architecture, provides whether
    /// the processor is not affected by branch type confusion.
    fn btc_no(&self) -> Option<bool>;

    /// Whether TSC aux virtualization is supported
    fn supports_tsc_aux_virtualization(&self, results: &CpuidResults) -> bool;
}

/// Architecture-specific behaviors for cpuid results during runtime
trait CpuidArchSupport: Sync + Send {
    /// Get the cpuid result of the leaf/subleaf but modified based on guest
    /// context
    fn process_guest_result(
        &self,
        leaf: CpuidFunction,
        subleaf: u32,
        result: &mut CpuidResult,
        guest_state: &CpuidGuestState,
        vps_per_socket: u32,
    );
}

/// Initialization parameters per isolation type for parsing cpuid results
pub enum CpuidResultsIsolationType<'a> {
    Snp { cpuid_pages: &'a [u8] },
    Tdx,
}

/// Errors that can be returned from validating the results of topology-related
/// leaves
#[derive(Error, Debug, PartialEq)]
pub enum TopologyError {
    #[error(
        "topology provided is inconsistent with hyperthreading configuration; apic core id size {0}"
    )]
    Hyperthreading(u8),
    #[error("processor count inconsistency; apic core id size {0}")]
    ProcessorCount(u8),
    #[error("threads per unit count is inconsistent")]
    ThreadsPerUnit,
}

/// Errors that can be returned while preparing and validating the cpuid results
/// that should be returned
#[derive(Error, Debug, PartialEq)]
pub enum CpuidResultsError {
    #[error("missing required result for leaf {0:?} subleaf {1:?}")]
    MissingRequiredResult(CpuidFunction, Option<u32>),
    #[error("provided topology values are inconsistent")]
    TopologyInconsistent(#[source] TopologyError),
    #[error("Invlpgb is required but unavailable")]
    InvlpgbUnavailable,
}

/// Leaves that are required on all architectures
const COMMON_REQUIRED_LEAVES: &[(CpuidFunction, Option<u32>)] = &[
    (CpuidFunction::VersionAndFeatures, None),
    (CpuidFunction::MonitorMwait, None),
    (CpuidFunction::ExtendedFeatures, Some(0)),
    (CpuidFunction::ExtendedTopologyEnumeration, Some(0)),
    (CpuidFunction::ExtendedTopologyEnumeration, Some(1)),
    (CpuidFunction::ExtendedVersionAndFeatures, None),
    (CpuidFunction::ExtendedL1CacheParameters, None),
    (CpuidFunction::ExtendedL2CacheParameters, None),
    (CpuidFunction::ExtendedPowerManagement, None),
    (CpuidFunction::ExtendedAddressSpaceSizes, None),
    (CpuidFunction::ExtendedBrandingString1, None),
    (CpuidFunction::ExtendedBrandingString2, None),
    (CpuidFunction::ExtendedBrandingString3, None),
    (CpuidFunction::ExtendedStateEnumeration, Some(0)),
    (CpuidFunction::ExtendedStateEnumeration, Some(1)),
];

// Note: these are required in the HCL implementation, but are marked reserved
// or are not listed in the AMD spec, so exclude them from the required list:
// - (CpuidFunction::CacheAndTlbInformation, None),
// - (CpuidFunction::ExtendedFeatures, Some(1)),
// - (CpuidFunction::CacheParameters, Some(0)),
// - (CpuidFunction::CacheParameters, Some(1)),
// - (CpuidFunction::CacheParameters, Some(2)),
// - (CpuidFunction::CacheParameters, Some(3)),
//
// This one is also required in the HCL implementation but is filtered out
// anyway, so exclude it as well:
// - (CpuidFunction::PowerManagement, None),

/// Expected cpuid result for a given leaf/subleaf, parsed from a trusted or
/// measured source
#[derive(Debug)]
pub struct ParsedCpuidEntry {
    /// Leaf
    leaf: CpuidFunction,
    /// Subleaf
    subleaf: u32,
    /// Result for the leaf/subleaf
    result: CpuidResult,
}

/// Prepares and caches the results that should be returned for hardware CVMs.
pub struct CpuidResults {
    results: HashMap<CpuidFunction, CpuidEntry>,
    max_extended_state: u64,
    arch_support: Box<dyn CpuidArchSupport>,
    vps_per_socket: u32,
}

// NOTE: Because subtables are used to calculate certain values _in order_ such
// as xsave, the data structure used must provide inorder traversal.
type CpuidSubtable = BTreeMap<u32, CpuidResult>;

/// Entry in [`CpuidResults`] for caching leaf value or its subleaves.
enum CpuidEntry {
    Leaf(CpuidResult),
    Subtable(CpuidSubtable),
}

/// Guest state needed to compute the cpuid result for a specific execution
/// state
pub struct CpuidGuestState {
    pub xfem: u64,
    pub xss: u64,
    pub cr4: u64,
    pub apic_id: u32,
}

const MAX_EXTENDED_STATE_ENUMERATION_SUBLEAF: u32 = 63;
const ZERO_CPUID_RESULT: CpuidResult = CpuidResult {
    eax: 0,
    ebx: 0,
    ecx: 0,
    edx: 0,
};

const CPUID_LEAF_B_MAX_SUBLEAF_INDEX: u32 = 1;
const CPUID_LEAF_B_LEVEL_NUMBER_SMT: u8 = 0;
const CPUID_LEAF_B_LEVEL_TYPE_SMT: u8 = 1;
const CPUID_LEAF_B_LEVEL_NUMBER_CORE: u8 = 1;
const CPUID_LEAF_B_LEVEL_TYPE_CORE: u8 = 2;

impl CpuidResults {
    pub fn new(params: CpuidResultsIsolationType<'_>) -> Result<Self, CpuidResultsError> {
        let (arch_initializer, arch_support) = match params {
            CpuidResultsIsolationType::Snp { cpuid_pages } => {
                assert!(
                    cpuid_pages.len() % size_of::<HvPspCpuidPage>() == 0 && !cpuid_pages.is_empty()
                );

                let snp_init: Box<dyn CpuidArchInitializer> =
                    Box::new(SnpCpuidInitializer::new(cpuid_pages));
                let snp_support: Box<dyn CpuidArchSupport> = Box::new(SnpCpuidSupport);

                (snp_init, snp_support)
            }
            CpuidResultsIsolationType::Tdx => {
                let tdx_init: Box<dyn CpuidArchInitializer> = Box::new(TdxCpuidInitializer {});
                let tdx_support: Box<dyn CpuidArchSupport> = Box::new(TdxCpuidSupport);
                (tdx_init, tdx_support)
            }
        };

        let (vendor_ebx, vendor_ecx, vendor_edx) = arch_initializer.vendor().to_ebx_ecx_edx();
        let mut results = HashMap::from([
            (
                CpuidFunction::VendorAndMaxFunction,
                CpuidEntry::Leaf(CpuidResult {
                    eax: arch_initializer.max_function(),
                    ebx: vendor_ebx,
                    ecx: vendor_ecx,
                    edx: vendor_edx,
                }),
            ),
            (
                CpuidFunction::ExtendedMaxFunction,
                CpuidEntry::Leaf(CpuidResult {
                    eax: arch_initializer.extended_max_function(),
                    ebx: vendor_ebx,
                    ecx: vendor_ecx,
                    edx: vendor_edx,
                }),
            ),
        ]);

        for ParsedCpuidEntry {
            leaf,
            subleaf,
            result,
        } in arch_initializer.cpuid_info()
        {
            if let Some(mask) = Self::leaf_mask(leaf, subleaf, arch_initializer.as_ref()) {
                let masked_result = {
                    let mut masked = mask.apply_mask(&result);
                    if leaf == CpuidFunction::ExtendedStateEnumeration && subleaf == 0 {
                        // These are inherently part of the architecture, so indicate this.
                        masked.eax |= xsave::X86X_XSAVE_LEGACY_FEATURES as u32;
                    }
                    masked
                };
                match results.entry(leaf) {
                    std::collections::hash_map::Entry::Occupied(mut entry) => {
                        // Only process the first value provided for a leaf and/or subleaf, and ignore any subsequent duplicates.
                        let mut skipped = false;
                        match entry.get_mut() {
                            CpuidEntry::Subtable(subtable) => {
                                assert!(mask.is_subleaf());

                                if subtable.get(&subleaf).is_none() {
                                    subtable.insert(subleaf, masked_result);
                                } else {
                                    skipped = true;
                                }
                            }
                            CpuidEntry::Leaf(_) => skipped = true,
                        }

                        if skipped {
                            tracing::warn!(
                                "cpuid result for leaf {} subleaf {} specified multiple times, ignoring duplicate with eax {}, ebx {}, ecx {}, edx {}",
                                leaf.0,
                                subleaf,
                                result.eax,
                                result.ebx,
                                result.ecx,
                                result.edx
                            );
                        }
                    }
                    std::collections::hash_map::Entry::Vacant(entry) => {
                        if mask.is_subleaf() {
                            let subtable = BTreeMap::from([(subleaf, masked_result)]);
                            entry.insert(CpuidEntry::Subtable(subtable));
                        } else {
                            entry.insert(CpuidEntry::Leaf(masked_result));
                        }
                    }
                };
            } else {
                tracing::trace!("Filtering out leaf {:x} subleaf {:x}", leaf.0, subleaf);
            }
        }

        let mut cached_results = Self {
            results,
            max_extended_state: 0, // will get updated as part of update_extended_state
            arch_support,
            vps_per_socket: 0, // will get updated as part of update_extended_topology
        };

        // Validate results before updating leaves because the updates might
        // have a dependency on certain leaves existing.
        cached_results.validate_results(arch_initializer.as_ref())?;
        cached_results.update_results(arch_initializer.as_ref())?;

        Ok(cached_results)
    }

    /// Retrieves the registered cpuid result for a given leaf/subleaf combination, if supported.
    pub fn registered_result(&self, leaf: CpuidFunction, subleaf: u32) -> CpuidResult {
        self.leaf_result_ref(leaf, Some(subleaf), false)
            .map_or(ZERO_CPUID_RESULT, |&result| result)
    }

    /// Retrieves the cpuid result of a given leaf/subleaf, tailored to the provided execution state
    pub fn guest_result(
        &self,
        leaf: CpuidFunction,
        subleaf: u32,
        guest_state: &CpuidGuestState,
    ) -> CpuidResult {
        let mut result = self.registered_result(leaf, subleaf);

        match leaf {
            CpuidFunction::VersionAndFeatures => {
                result.ecx = cpuid::VersionAndFeaturesEcx::from(result.ecx)
                    .with_os_xsave(guest_state.cr4 & x86defs::X64_CR4_OSXSAVE != 0)
                    .with_x2_apic(true)
                    .into();
                result.ebx = cpuid::VersionAndFeaturesEbx::from(result.ebx)
                    .with_initial_apic_id(guest_state.apic_id as u8)
                    .into();
            }
            CpuidFunction::ExtendedTopologyEnumeration => {
                if subleaf <= CPUID_LEAF_B_MAX_SUBLEAF_INDEX {
                    result.edx = guest_state.apic_id;
                }
            }
            CpuidFunction::ExtendedStateEnumeration => {
                if subleaf == 0 {
                    result.ebx = self.xsave_size(guest_state.xfem); // XsaveMaxSizeEnabled
                } else if subleaf == 1
                    && cpuid::ExtendedStateEnumerationSubleaf1Eax::from(result.eax).xsave_s()
                {
                    // XsavesMaxSizeEnabled
                    result.ebx = self.compacted_xsave_size(guest_state.xfem | guest_state.xss);
                }
            }
            _ => self.arch_support.process_guest_result(
                leaf,
                subleaf,
                &mut result,
                guest_state,
                self.vps_per_socket,
            ),
        }

        result
    }

    /// Gets an immutable reference to a (sub)leaf's result. Not all callers may
    /// necessarily know whether the subleaf parameter is valid, e.g. if the
    /// value came from a guest register. Using enforce_subleaf means that the
    /// caller knows whether or not the subleaf parameter is valid and would
    /// like to enforce that the returned result is consistent with the
    /// type of the cpuid entry.
    fn leaf_result_ref(
        &self,
        leaf: CpuidFunction,
        subleaf: Option<u32>,
        enforce_subleaf: bool,
    ) -> Option<&CpuidResult> {
        self.results.get(&leaf).and_then(|entry| match entry {
            CpuidEntry::Leaf(result) => {
                if !enforce_subleaf || subleaf.is_none() {
                    Some(result)
                } else {
                    None
                }
            }
            CpuidEntry::Subtable(subtable) => subleaf.and_then(|sl| subtable.get(&sl)),
        })
    }

    /// Get mutable reference to a leaf or subleaf. Enforces consistency of the
    /// subleaf parameter with the type of the cpuid entry.
    fn leaf_result_mut_ref(
        &mut self,
        leaf: CpuidFunction,
        subleaf: Option<u32>,
    ) -> Option<&mut CpuidResult> {
        self.results.get_mut(&leaf).and_then(|entry| match entry {
            CpuidEntry::Leaf(result) => {
                if subleaf.is_none() {
                    Some(result)
                } else {
                    None
                }
            }
            CpuidEntry::Subtable(subtable) => {
                if let Some(subleaf) = subleaf {
                    return subtable.get_mut(&subleaf);
                }
                None
            }
        })
    }

    /// Checks that the required results exist and have the expected values.
    /// Extended State Enumeration subleaves 2+ are checked separately.
    fn validate_results(
        &self,
        arch_initializer: &dyn CpuidArchInitializer,
    ) -> Result<(), CpuidResultsError> {
        for &(leaf, subleaf) in COMMON_REQUIRED_LEAVES {
            if self.leaf_result_ref(leaf, subleaf, true).is_none() {
                return Err(CpuidResultsError::MissingRequiredResult(leaf, subleaf));
            }
        }

        arch_initializer.validate_results(self)
    }

    /// For updating the parsed results to their final values.
    fn update_results(
        &mut self,
        arch_initializer: &dyn CpuidArchInitializer,
    ) -> Result<(), CpuidResultsError> {
        self.update_extended_state(arch_initializer)?;
        self.update_extended_address_space_sizes(arch_initializer);
        self.update_extended_topology(arch_initializer)?;

        let version_and_features = self
            .leaf_result_mut_ref(CpuidFunction::VersionAndFeatures, None)
            .expect("validated this exists");

        version_and_features.ecx = cpuid::VersionAndFeaturesEcx::from(version_and_features.ecx)
            .with_hypervisor_present(true)
            .into();

        if !arch_initializer.supports_tsc_aux_virtualization(self) {
            // Inhibit availability of RDTSCP and RDPID if TSC_AUX virtualization is
            // not supported.
            let extended_version_and_features = self
                .leaf_result_mut_ref(CpuidFunction::ExtendedVersionAndFeatures, None)
                .expect("validated this exists");
            extended_version_and_features.edx =
                cpuid::ExtendedVersionAndFeaturesEdx::from(extended_version_and_features.edx)
                    .with_rdtscp(false)
                    .into();

            let extended_features = self
                .leaf_result_mut_ref(CpuidFunction::ExtendedFeatures, Some(0))
                .expect("validated this exists");
            extended_features.ecx = cpuid::ExtendedFeatureSubleaf0Ecx::from(extended_features.ecx)
                .with_rd_pid(false)
                .into();
        }

        Ok(())
    }

    /// Updates the extended state enumeration (leaf 0xd) subleaves
    fn update_extended_state(
        &mut self,
        arch_initializer: &dyn CpuidArchInitializer,
    ) -> Result<(), CpuidResultsError> {
        let extended_state_subtable = {
            if let CpuidEntry::Subtable(extended_state_subtable) = self
                .results
                .get_mut(&CpuidFunction::ExtendedStateEnumeration)
                .expect("validated this leaf exists")
            {
                extended_state_subtable
            } else {
                unreachable!("should have been constructed as a subtable")
            }
        };

        let max_xfem = {
            let CpuidResult {
                eax: feature_mask_low,
                ebx: _,
                ecx: _,
                edx: feature_mask_high,
            } = extended_state_subtable[&0]; // validated subleaf 0 exists

            ((feature_mask_high as u64) << 32) | (feature_mask_low as u64)
        };

        let max_xss = {
            let CpuidResult {
                eax,
                ebx: _,
                ecx: xss_mask_low,
                edx: xss_mask_high,
            } = extended_state_subtable[&1]; // validated subleaf 1 exists

            let subleaf1 = cpuid::ExtendedStateEnumerationSubleaf1Eax::from(eax);
            if subleaf1.xsave_s() && subleaf1.xsave_c() {
                ((xss_mask_high as u64) << 32) | xss_mask_low as u64
            } else {
                0
            }
        };

        let max_extended_state = max_xfem | max_xss;

        arch_initializer
            .process_extended_state_subleaves(extended_state_subtable, max_extended_state)?;

        let xsave_size = self.xsave_size(max_xfem);

        if let CpuidEntry::Subtable(extended_state_subtable) = self
            .results
            .get_mut(&CpuidFunction::ExtendedStateEnumeration)
            .expect("validated this leaf exists")
        {
            let CpuidResult {
                eax: _,
                ebx: _,
                ecx: xsave_max_size_hw,
                edx: _,
            } = extended_state_subtable
                .get_mut(&0)
                .expect("validated this subleaf exists");

            *xsave_max_size_hw = xsave_size;

            let CpuidResult {
                eax: _,
                ebx: _,
                ecx: xss_mask_low,
                edx: xss_mask_high,
            } = extended_state_subtable
                .get_mut(&1)
                .expect("validated this subleaf exists");

            if max_xss == 0 {
                *xss_mask_low = 0;
                *xss_mask_high = 0;
            }

            let subleaves: Vec<u32> = extended_state_subtable.keys().cloned().collect();
            for subleaf in subleaves {
                assert!(subleaf <= MAX_EXTENDED_STATE_ENUMERATION_SUBLEAF);
                if (subleaf >= xsave::X86X_XSAVE_NUM_LEGACY_FEATURES)
                    && ((1u64 << subleaf) & max_extended_state) == 0
                {
                    extended_state_subtable.remove(&subleaf);
                }
            }
        } else {
            unreachable!("should have constructed this cpuid function as a subleaf")
        }

        // Suppress the availability of CET if the required XSS support has been
        // inhibited.
        if (max_xss & xsave::XSAVE_SUPERVISOR_FEATURE_CET) != xsave::XSAVE_SUPERVISOR_FEATURE_CET {
            let extended_features_entry = self
                .leaf_result_mut_ref(CpuidFunction::ExtendedFeatures, Some(0))
                .expect("validated this leaf exists");

            let mut new_ecx = cpuid::ExtendedFeatureSubleaf0Ecx::from(extended_features_entry.ecx);
            new_ecx.set_cet_ss(false);

            extended_features_entry.ecx = new_ecx.into();
        }

        self.max_extended_state = max_extended_state;

        Ok(())
    }

    fn calculate_xsave_size<F>(&self, mask: u64, area_size_fn: F) -> u32
    where
        F: Fn(u32, CpuidResult) -> u32,
    {
        let mut area_size = xsave::XSAVE_MINIMUM_XSAVE_AREA_SIZE;
        let summary_mask = mask & !xsave::X86X_XSAVE_LEGACY_FEATURES;

        if let CpuidEntry::Subtable(extended_state_subtable) = self
            .results
            .get(&CpuidFunction::ExtendedStateEnumeration)
            .expect("validated this leaf exists")
        {
            // The order of the save area layout is not necessarily tied to the
            // order of the features in the feature bitmask. Thus, do a full
            // search of all features to find the largest potential save area
            // size.

            for (subleaf, result) in extended_state_subtable {
                if (1u64 << subleaf) & summary_mask != 0 {
                    area_size = area_size_fn(area_size, *result);
                }
            }
        } else {
            unreachable!("should have constructed this function as a subleaf")
        }

        area_size
    }

    /// Calculates the save area size required for the specified mask of XSAVE
    /// features
    pub fn xsave_size(&self, xfem: u64) -> u32 {
        let area_size_fn = |current_area_size: u32,
                            CpuidResult {
                                eax: feature_size,
                                ebx: feature_offset,
                                ecx: _,
                                edx: _,
                            }|
         -> u32 { current_area_size.max(feature_size + feature_offset) };

        self.calculate_xsave_size(xfem, area_size_fn)
    }

    /// calculates the save area size required to save the specified set of user
    /// and supervisor XSAVE state components in compacted format.
    fn compacted_xsave_size(&self, mask: u64) -> u32 {
        let area_size_fn = |current_area_size: u32,
                            CpuidResult {
                                eax: feature_size,
                                ebx: _,
                                ecx,
                                edx: _,
                            }|
         -> u32 {
            let mut area_size = current_area_size;
            // TODO: u32::next_multiple_of is currently unstable
            let round_up = |value: u32, alignment: u32| -> u32 {
                (value + (alignment - 1)) & !(alignment - 1)
            };

            if cpuid::ExtendedStateEnumerationSubleafNEcx::from(ecx).aligned() {
                area_size = round_up(area_size, xsave::XSAVE_REQUIRED_XSAVE_AREA_ALIGNMENT);
            }

            area_size += feature_size; // eax is feature size
            area_size
        };

        self.calculate_xsave_size(mask, area_size_fn)
    }

    fn update_extended_topology(
        &mut self,
        arch_initializer: &dyn CpuidArchInitializer,
    ) -> Result<(), CpuidResultsError> {
        let version_and_features = self
            .leaf_result_ref(CpuidFunction::VersionAndFeatures, None, true)
            .expect("validated this exists");

        let address_space_sizes_ecx = cpuid::ExtendedAddressSpaceSizesEcx::from(
            self.leaf_result_ref(CpuidFunction::ExtendedAddressSpaceSizes, None, true)
                .expect("validated this exists")
                .ecx,
        );

        let processor_topology_ebx = self
            .leaf_result_ref(CpuidFunction::ProcessorTopologyDefinition, None, true)
            .map(|result| cpuid::ProcessorTopologyDefinitionEbx::from(result.ebx));

        let extended_topology = arch_initializer.extended_topology(
            cpuid::VersionAndFeaturesEbx::from(version_and_features.ebx),
            cpuid::VersionAndFeaturesEdx::from(version_and_features.edx),
            address_space_sizes_ecx,
            processor_topology_ebx,
        )?;

        if let Some(subleaf0) = extended_topology.subleaf0 {
            *(self
                .leaf_result_mut_ref(CpuidFunction::ExtendedTopologyEnumeration, Some(0))
                .expect("validated this exists")) = subleaf0;
        }

        if let Some(subleaf1) = extended_topology.subleaf1 {
            *(self
                .leaf_result_mut_ref(CpuidFunction::ExtendedTopologyEnumeration, Some(1))
                .expect("validated this exists")) = subleaf1;
        }

        self.vps_per_socket = extended_topology.vps_per_socket;

        Ok(())
    }

    fn update_extended_address_space_sizes(&mut self, arch_initializer: &dyn CpuidArchInitializer) {
        let extended_address_space_sizes = self
            .leaf_result_mut_ref(CpuidFunction::ExtendedAddressSpaceSizes, None)
            .expect("validated this exists");

        let mut updated_sizes =
            cpuid::ExtendedAddressSpaceSizesEbx::from(extended_address_space_sizes.ebx);

        if let Some(btc_no) = arch_initializer.btc_no() {
            updated_sizes.set_btc_no(btc_no);
        }

        // If IBPB is not present, do not enumerate STIBP or IBRS. This is not strictly necessary since
        // the paravisor does not (currently) use IBPB, but there is no harm in enforcing something
        // that the architecture otherwise supports.
        if !updated_sizes.ibpb() {
            updated_sizes.set_ibrs(false);
            updated_sizes.set_stibp(false);
        }

        extended_address_space_sizes.ebx = updated_sizes.into();
    }
}
