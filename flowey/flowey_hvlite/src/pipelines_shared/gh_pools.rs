// Copyright (C) Microsoft Corporation. All rights reserved.

//! Centralized list of constants enumerating available GitHub build pools.

#![allow(unused)]

use flowey::pipeline::prelude::*;

pub fn default_x86_pool(job_platform: JobPlatform) -> GhRunner {
    match job_platform {
        JobPlatform::Windows => windows_amd_self_hosted(),
        JobPlatform::Linux => linux_self_hosted(),
    }
}

pub fn default_gh_hosted(job_platform: JobPlatform) -> GhRunner {
    match job_platform {
        JobPlatform::Windows => gh_hosted_windows(),
        JobPlatform::Linux => gh_hosted_linux(),
    }
}

pub fn windows_amd_self_hosted() -> GhRunner {
    GhRunner::SelfHosted(vec![
        "self-hosted".to_string(),
        "1ES.Pool=HvLite-GitHub-Win-Pool-WestUS3".to_string(),
    ])
}

pub fn windows_intel_self_hosted() -> GhRunner {
    GhRunner::SelfHosted(vec![
        "self-hosted".to_string(),
        "1ES.Pool=HvLite-GitHub-Win-Pool-Intel-WestUS3".to_string(),
        "1ES.ImageOverride=HvLite-CI-Win-Ge-Image-256GB".to_string(),
    ])
}

/// This overrides the default image with a larger disk image for use with
/// jobs that require more than the default disk space (e.g. to ensure vmm_tests
/// have enough space to download test VHDs)
pub fn windows_amd_self_hosted_largedisk() -> GhRunner {
    GhRunner::SelfHosted(vec![
        "self-hosted".to_string(),
        "1ES.Pool=HvLite-GitHub-Win-Pool-WestUS3".to_string(),
        "1ES.ImageOverride=HvLite-CI-Win-Ge-Image-256GB".to_string(),
    ])
}

/// This overrides the default image with a larger disk image for use with
/// jobs that require more than the default disk space (e.g. to ensure vmm_tests
/// have enough space to download test VHDs)
pub fn windows_intel_self_hosted_largedisk() -> GhRunner {
    GhRunner::SelfHosted(vec![
        "self-hosted".to_string(),
        "1ES.Pool=HvLite-GitHub-Win-Pool-Intel-WestUS3".to_string(),
        "1ES.ImageOverride=HvLite-CI-Win-Ge-Image-256GB".to_string(),
    ])
}

pub fn linux_self_hosted() -> GhRunner {
    GhRunner::SelfHosted(vec![
        "self-hosted".to_string(),
        "1ES.Pool=HvLite-GitHub-Linux-Pool-WestUS3".to_string(),
    ])
}

pub fn gh_hosted_windows() -> GhRunner {
    GhRunner::GhHosted(GhRunnerOsLabel::WindowsLatest)
}

pub fn gh_hosted_linux() -> GhRunner {
    GhRunner::GhHosted(GhRunnerOsLabel::UbuntuLatest)
}
