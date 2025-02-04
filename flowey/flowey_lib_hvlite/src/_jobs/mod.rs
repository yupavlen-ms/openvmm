// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Defines top-level "job nodes" which can be composed when defining a flowey
//! pipeline using [`flowey::pipeline::prelude::PipelineJob::dep_on`].

pub mod all_good_job;
pub mod build_and_publish_guest_test_uefi;
pub mod build_and_publish_guide;
pub mod build_and_publish_hypestv;
pub mod build_and_publish_igvmfilegen;
pub mod build_and_publish_nextest_unit_tests_archive;
pub mod build_and_publish_nextest_vmm_tests_archive;
pub mod build_and_publish_ohcldiag_dev;
pub mod build_and_publish_openhcl_igvm_from_recipe;
pub mod build_and_publish_openvmm;
pub mod build_and_publish_openvmm_hcl_baseline;
pub mod build_and_publish_pipette;
pub mod build_and_publish_rustdoc;
pub mod build_and_publish_vmgs_lib;
pub mod build_and_publish_vmgstool;
pub mod build_and_run_doc_tests;
pub mod build_and_run_nextest_unit_tests;
pub mod build_and_run_nextest_vmm_tests;
pub mod cfg_common;
pub mod cfg_gh_azure_login;
pub mod cfg_hvlite_reposource;
pub mod cfg_versions;
pub mod check_clippy;
pub mod check_openvmm_hcl_size;
pub mod check_xtask_fmt;
pub mod consolidate_and_publish_gh_pages;
pub mod consume_and_test_nextest_unit_tests_archive;
pub mod consume_and_test_nextest_vmm_tests_archive;
pub mod local_build_igvm;
pub mod local_custom_vmfirmwareigvm_dll;
pub mod local_restore_packages;
pub mod test_local_flowey_build_igvm;
