// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Centralized list of constants enumerating available GitHub build pools.

use flowey::node::prelude::FlowPlatformLinuxDistro;
use flowey::pipeline::prelude::*;

pub fn default_x86_pool(platform: FlowPlatform) -> GhRunner {
    match platform {
        FlowPlatform::Windows => windows_amd_self_hosted(),
        FlowPlatform::Linux(FlowPlatformLinuxDistro::Ubuntu) => linux_self_hosted(),
        platform => panic!("unsupported platform {platform}"),
    }
}

pub fn default_gh_hosted(platform: FlowPlatform) -> GhRunner {
    match platform {
        FlowPlatform::Windows => gh_hosted_windows(),
        FlowPlatform::Linux(FlowPlatformLinuxDistro::Ubuntu) => gh_hosted_linux(),
        platform => panic!("unsupported platform {platform}"),
    }
}

pub fn windows_amd_self_hosted() -> GhRunner {
    GhRunner::SelfHosted(vec![
        "self-hosted".to_string(),
        "1ES.Pool=OpenVMM-GitHub-Win-Pool-WestUS3".to_string(),
    ])
}

pub fn windows_intel_self_hosted() -> GhRunner {
    GhRunner::SelfHosted(vec![
        "self-hosted".to_string(),
        "1ES.Pool=OpenVMM-GitHub-Win-Pool-Intel-WestUS3".to_string(),
        "1ES.ImageOverride=HvLite-CI-Win-Ge-Image-256GB".to_string(),
    ])
}

/// This overrides the default image with a larger disk image for use with
/// jobs that require more than the default disk space (e.g. to ensure vmm_tests
/// have enough space to download test VHDs)
pub fn windows_amd_self_hosted_largedisk() -> GhRunner {
    GhRunner::SelfHosted(vec![
        "self-hosted".to_string(),
        "1ES.Pool=OpenVMM-GitHub-Win-Pool-WestUS3".to_string(),
        "1ES.ImageOverride=HvLite-CI-Win-Ge-Image-256GB".to_string(),
    ])
}

/// This overrides the default image with a larger disk image for use with
/// jobs that require more than the default disk space (e.g. to ensure vmm_tests
/// have enough space to download test VHDs)
pub fn windows_intel_self_hosted_largedisk() -> GhRunner {
    GhRunner::SelfHosted(vec![
        "self-hosted".to_string(),
        "1ES.Pool=OpenVMM-GitHub-Win-Pool-Intel-WestUS3".to_string(),
        "1ES.ImageOverride=HvLite-CI-Win-Ge-Image-256GB".to_string(),
    ])
}

pub fn linux_self_hosted() -> GhRunner {
    GhRunner::SelfHosted(vec![
        "self-hosted".to_string(),
        "1ES.Pool=OpenVMM-GitHub-Linux-Pool-WestUS3".to_string(),
        "1ES.ImageOverride=MMSUbuntu22.04-256GB".to_string(),
    ])
}

pub fn gh_hosted_windows() -> GhRunner {
    GhRunner::GhHosted(GhRunnerOsLabel::WindowsLatest)
}

pub fn gh_hosted_linux() -> GhRunner {
    GhRunner::GhHosted(GhRunnerOsLabel::UbuntuLatest)
}

pub fn windows_arm_self_hosted_baremetal() -> GhRunner {
    GhRunner::SelfHosted(vec![
        "self-hosted".to_string(),
        "Windows".to_string(),
        "ARM64".to_string(),
        "Baremetal".to_string(),
    ])
}
