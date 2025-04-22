// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! See [`CheckinGatesCli`]

use flowey::node::prelude::FlowPlatformLinuxDistro;
use flowey::node::prelude::GhPermission;
use flowey::node::prelude::GhPermissionValue;
use flowey::node::prelude::ReadVar;
use flowey::pipeline::prelude::*;
use flowey_lib_common::git_checkout::RepoSource;
use flowey_lib_hvlite::_jobs::build_and_publish_openhcl_igvm_from_recipe::OpenhclIgvmBuildParams;
use flowey_lib_hvlite::build_openhcl_igvm_from_recipe::OpenhclIgvmRecipe;
use flowey_lib_hvlite::build_openvmm_hcl::OpenvmmHclBuildProfile;
use flowey_lib_hvlite::run_cargo_build::common::CommonArch;
use flowey_lib_hvlite::run_cargo_build::common::CommonPlatform;
use flowey_lib_hvlite::run_cargo_build::common::CommonProfile;
use flowey_lib_hvlite::run_cargo_build::common::CommonTriple;
use std::path::PathBuf;
use target_lexicon::Triple;
use vmm_test_images::KnownIso;
use vmm_test_images::KnownVhd;

#[derive(Copy, Clone, clap::ValueEnum)]
enum PipelineConfig {
    /// Run on all PRs targeting the OpenVMM github repo
    Pr,
    /// Run on all commits that land in OpenVMM's `main` branch.
    ///
    /// The key difference between the CI and PR pipelines is whether things are
    /// being built in `release` mode.
    Ci,
}

/// A unified pipeline defining all checkin gates required to land a commit in
/// the OpenVMM repo.
#[derive(clap::Args)]
pub struct CheckinGatesCli {
    /// Which pipeline configuration to use.
    #[clap(long)]
    config: PipelineConfig,

    #[clap(flatten)]
    local_run_args: Option<crate::pipelines_shared::cfg_common_params::LocalRunArgs>,

    /// Set custom path to search for / download VMM tests disk-images
    #[clap(long)]
    vmm_tests_disk_cache_dir: Option<PathBuf>,
}

impl IntoPipeline for CheckinGatesCli {
    fn into_pipeline(self, backend_hint: PipelineBackendHint) -> anyhow::Result<Pipeline> {
        let Self {
            config,
            local_run_args,
            vmm_tests_disk_cache_dir,
        } = self;

        let release = match config {
            PipelineConfig::Ci => true,
            PipelineConfig::Pr => false,
        };

        let mut pipeline = Pipeline::new();

        // configure pr/ci branch triggers and add gh pipeline name
        {
            let branches = vec!["main".into(), "release/*".into()];
            match config {
                PipelineConfig::Ci => {
                    pipeline
                        .gh_set_ci_triggers(GhCiTriggers {
                            branches,
                            ..Default::default()
                        })
                        .gh_set_name("[flowey] OpenVMM CI");
                }
                PipelineConfig::Pr => {
                    pipeline
                        .gh_set_pr_triggers(GhPrTriggers {
                            branches,
                            ..GhPrTriggers::new_draftable()
                        })
                        .gh_set_name("[flowey] OpenVMM PR");
                }
            }
        }

        let openvmm_repo_source = {
            if matches!(backend_hint, PipelineBackendHint::Local) {
                RepoSource::ExistingClone(ReadVar::from_static(crate::repo_root()))
            } else if matches!(backend_hint, PipelineBackendHint::Github) {
                RepoSource::GithubSelf
            } else {
                anyhow::bail!(
                    "Unsupported backend: Checkin Gates only supports Local and Github backends"
                );
            }
        };

        if let RepoSource::GithubSelf = &openvmm_repo_source {
            pipeline.gh_set_flowey_bootstrap_template(
                crate::pipelines_shared::gh_flowey_bootstrap_template::get_template(),
            );
        }

        let cfg_common_params = crate::pipelines_shared::cfg_common_params::get_cfg_common_params(
            &mut pipeline,
            backend_hint,
            local_run_args,
        )?;

        pipeline.inject_all_jobs_with(move |job| {
            job.dep_on(&cfg_common_params)
                .dep_on(|_| flowey_lib_hvlite::_jobs::cfg_versions::Request {})
                .dep_on(
                    |_| flowey_lib_hvlite::_jobs::cfg_hvlite_reposource::Params {
                        hvlite_repo_source: openvmm_repo_source.clone(),
                    },
                )
                .gh_grant_permissions::<flowey_lib_common::git_checkout::Node>([(
                    GhPermission::Contents,
                    GhPermissionValue::Read,
                )])
                .gh_grant_permissions::<flowey_lib_common::gh_task_azure_login::Node>([(
                    GhPermission::IdToken,
                    GhPermissionValue::Write,
                )])
        });

        let openhcl_musl_target = |arch: CommonArch| -> Triple {
            CommonTriple::Common {
                arch,
                platform: CommonPlatform::LinuxMusl,
            }
            .as_triple()
        };

        // initialize the various VMM tests nextest archive artifacts
        let (pub_vmm_tests_archive_linux_x86, use_vmm_tests_archive_linux_x86) =
            pipeline.new_typed_artifact("x64-linux-vmm-tests-archive");
        let (pub_vmm_tests_archive_windows_x86, use_vmm_tests_archive_windows_x86) =
            pipeline.new_typed_artifact("x64-windows-vmm-tests-archive");
        let (pub_vmm_tests_archive_windows_aarch64, use_vmm_tests_archive_windows_aarch64) =
            pipeline.new_typed_artifact("aarch64-windows-vmm-tests-archive");

        // wrap each publish handle in an option, so downstream code can
        // `.take()` the handle when emitting the corresponding job
        let mut pub_vmm_tests_archive_linux_x86 = Some(pub_vmm_tests_archive_linux_x86);
        let mut pub_vmm_tests_archive_windows_x86 = Some(pub_vmm_tests_archive_windows_x86);
        let mut pub_vmm_tests_archive_windows_aarch64 = Some(pub_vmm_tests_archive_windows_aarch64);

        // initialize the various "VmmTestsArtifactsBuilder" containers, which
        // are used to "skim off" various artifacts that the VMM test jobs
        // require.
        let mut vmm_tests_artifacts_linux_x86 =
            vmm_tests_artifact_builders::VmmTestsArtifactsBuilderLinuxX86::default();
        let mut vmm_tests_artifacts_windows_x86 =
            vmm_tests_artifact_builders::VmmTestsArtifactsBuilderWindowsX86::default();
        let mut vmm_tests_artifacts_windows_aarch64 =
            vmm_tests_artifact_builders::VmmTestsArtifactsBuilderWindowsAarch64::default();

        // We need to maintain a list of all jobs, so we can hang the "all good"
        // job off of them. This is requires because github status checks only allow
        // specifying jobs, and not workflows.
        // There's more info in the following discussion:
        // <https://github.com/orgs/community/discussions/12395>
        let mut all_jobs = Vec::new();

        // emit mdbook guide build job
        let (pub_guide, use_guide) = pipeline.new_artifact("guide");
        let job = pipeline
            .new_job(
                FlowPlatform::Linux(FlowPlatformLinuxDistro::Ubuntu),
                FlowArch::X86_64,
                "build mdbook guide",
            )
            .gh_set_pool(crate::pipelines_shared::gh_pools::default_gh_hosted(
                FlowPlatform::Linux(FlowPlatformLinuxDistro::Ubuntu),
            ))
            .dep_on(
                |ctx| flowey_lib_hvlite::_jobs::build_and_publish_guide::Params {
                    artifact_dir: ctx.publish_artifact(pub_guide),
                    done: ctx.new_done_handle(),
                },
            )
            .finish();

        all_jobs.push(job);

        // emit rustdoc jobs
        let (pub_rustdoc_linux, use_rustdoc_linux) = pipeline.new_artifact("x64-linux-rustdoc");
        let (pub_rustdoc_win, use_rustdoc_win) = pipeline.new_artifact("x64-windows-rustdoc");
        for (target, platform, pub_rustdoc) in [
            (
                CommonTriple::X86_64_WINDOWS_MSVC,
                FlowPlatform::Windows,
                pub_rustdoc_win,
            ),
            (
                CommonTriple::X86_64_LINUX_GNU,
                FlowPlatform::Linux(FlowPlatformLinuxDistro::Ubuntu),
                pub_rustdoc_linux,
            ),
        ] {
            let job = pipeline
                .new_job(
                    platform,
                    FlowArch::X86_64,
                    format!("build and check docs [x64-{platform}]"),
                )
                .gh_set_pool(crate::pipelines_shared::gh_pools::default_x86_pool(
                    platform,
                ))
                .dep_on(
                    |ctx| flowey_lib_hvlite::_jobs::build_and_publish_rustdoc::Params {
                        target_triple: target.as_triple(),
                        artifact_dir: ctx.publish_artifact(pub_rustdoc),
                        done: ctx.new_done_handle(),
                    },
                )
                .finish();

            all_jobs.push(job);
        }

        // emit consolidated gh pages publish job
        if matches!(config, PipelineConfig::Ci) {
            let artifact_dir = if matches!(backend_hint, PipelineBackendHint::Local) {
                let (publish, _use) = pipeline.new_artifact("gh-pages");
                Some(publish)
            } else {
                None
            };

            let job = pipeline
                .new_job(FlowPlatform::Linux(FlowPlatformLinuxDistro::Ubuntu), FlowArch::X86_64, "publish openvmm.dev")
                .gh_set_pool(crate::pipelines_shared::gh_pools::default_gh_hosted(
                    FlowPlatform::Linux(FlowPlatformLinuxDistro::Ubuntu),
                ))
                .dep_on(
                    |ctx| flowey_lib_hvlite::_jobs::consolidate_and_publish_gh_pages::Params {
                        rustdoc_linux: ctx.use_artifact(&use_rustdoc_linux),
                        rustdoc_windows: ctx.use_artifact(&use_rustdoc_win),
                        guide: ctx.use_artifact(&use_guide),
                        artifact_dir: artifact_dir.map(|x| ctx.publish_artifact(x)),
                        done: ctx.new_done_handle(),
                    },
                )
                .gh_grant_permissions::<flowey_lib_hvlite::_jobs::consolidate_and_publish_gh_pages::Node>([
                    (GhPermission::IdToken, GhPermissionValue::Write),
                    (GhPermission::Pages, GhPermissionValue::Write),
                ])
                .finish();

            all_jobs.push(job);
        }

        // emit xtask fmt job
        {
            let windows_fmt_job = pipeline
                .new_job(
                    FlowPlatform::Windows,
                    FlowArch::X86_64,
                    "xtask fmt (windows)",
                )
                .gh_set_pool(crate::pipelines_shared::gh_pools::default_gh_hosted(
                    FlowPlatform::Windows,
                ))
                .dep_on(|ctx| flowey_lib_hvlite::_jobs::check_xtask_fmt::Request {
                    target: CommonTriple::X86_64_WINDOWS_MSVC,
                    done: ctx.new_done_handle(),
                })
                .finish();

            let linux_fmt_job = pipeline
                .new_job(
                    FlowPlatform::Linux(FlowPlatformLinuxDistro::Ubuntu),
                    FlowArch::X86_64,
                    "xtask fmt (linux)",
                )
                .gh_set_pool(crate::pipelines_shared::gh_pools::default_x86_pool(
                    FlowPlatform::Linux(FlowPlatformLinuxDistro::Ubuntu),
                ))
                .dep_on(|ctx| flowey_lib_hvlite::_jobs::check_xtask_fmt::Request {
                    target: CommonTriple::X86_64_LINUX_GNU,
                    done: ctx.new_done_handle(),
                })
                .finish();

            // cut down on extra noise by having the linux check run first, and
            // then if it passes, run the windows checks just in case there is a
            // difference between the two.
            pipeline.non_artifact_dep(&windows_fmt_job, &linux_fmt_job);

            all_jobs.push(linux_fmt_job);
            all_jobs.push(windows_fmt_job);
        }

        // emit windows build machine jobs
        //
        // In order to ensure we start running VMM tests as soon as possible, we emit
        // two separate windows job per arch - one for artifacts in the VMM tests
        // hotpath, and another for any auxiliary artifacts that aren't
        // required by VMM tests.
        for arch in [CommonArch::Aarch64, CommonArch::X86_64] {
            let arch_tag = match arch {
                CommonArch::X86_64 => "x64",
                CommonArch::Aarch64 => "aarch64",
            };

            // artifacts which _are_ in the VMM tests "hot path"
            let (pub_openvmm, use_openvmm) =
                pipeline.new_typed_artifact(format!("{arch_tag}-windows-openvmm"));

            let (pub_pipette_windows, use_pipette_windows) =
                pipeline.new_typed_artifact(format!("{arch_tag}-windows-pipette"));

            let (pub_tmk_vmm, use_tmk_vmm) =
                pipeline.new_typed_artifact(format!("{arch_tag}-windows-tmk_vmm"));

            // filter off interesting artifacts required by the VMM tests job
            match arch {
                CommonArch::X86_64 => {
                    vmm_tests_artifacts_linux_x86.use_pipette_windows =
                        Some(use_pipette_windows.clone());
                    vmm_tests_artifacts_windows_x86.use_openvmm = Some(use_openvmm.clone());
                    vmm_tests_artifacts_windows_x86.use_pipette_windows =
                        Some(use_pipette_windows.clone());
                    vmm_tests_artifacts_windows_x86.use_tmk_vmm = Some(use_tmk_vmm.clone());
                }
                CommonArch::Aarch64 => {
                    vmm_tests_artifacts_windows_aarch64.use_openvmm = Some(use_openvmm.clone());
                    vmm_tests_artifacts_windows_aarch64.use_pipette_windows =
                        Some(use_pipette_windows.clone());
                    vmm_tests_artifacts_windows_aarch64.use_tmk_vmm = Some(use_tmk_vmm.clone());
                }
            }
            // emit a job for artifacts which _are not_ in the VMM tests "hot
            // path"
            // artifacts which _are not_ in the VMM tests "hot path"
            let (pub_igvmfilegen, _use_igvmfilegen) =
                pipeline.new_typed_artifact(format!("{arch_tag}-windows-igvmfilegen"));
            let (pub_vmgs_lib, _use_vmgs_lib) =
                pipeline.new_typed_artifact(format!("{arch_tag}-windows-vmgs_lib"));
            let (pub_vmgstool, _use_vmgstool) =
                pipeline.new_typed_artifact(format!("{arch_tag}-windows-vmgstool"));
            let (pub_hypestv, _use_hypestv) =
                pipeline.new_typed_artifact(format!("{arch_tag}-windows-hypestv"));
            let (pub_ohcldiag_dev, _use_ohcldiag_dev) =
                pipeline.new_typed_artifact(format!("{arch_tag}-windows-ohcldiag-dev"));

            let job = pipeline
                .new_job(
                    FlowPlatform::Windows,
                    FlowArch::X86_64,
                    format!("build artifacts (not for VMM tests) [{arch_tag}-windows]"),
                )
                .gh_set_pool(crate::pipelines_shared::gh_pools::default_x86_pool(
                    FlowPlatform::Windows,
                ))
                .dep_on(|ctx| flowey_lib_hvlite::build_vmgstool::Request {
                    target: CommonTriple::Common {
                        arch,
                        platform: CommonPlatform::WindowsMsvc,
                    },
                    profile: CommonProfile::from_release(release),
                    with_crypto: true,
                    vmgstool: ctx.publish_typed_artifact(pub_vmgstool),
                })
                .dep_on(|ctx| flowey_lib_hvlite::build_hypestv::Request {
                    target: CommonTriple::Common {
                        arch,
                        platform: CommonPlatform::WindowsMsvc,
                    },
                    profile: CommonProfile::from_release(release),
                    hypestv: ctx.publish_typed_artifact(pub_hypestv),
                })
                .dep_on(|ctx| flowey_lib_hvlite::build_and_test_vmgs_lib::Request {
                    target: CommonTriple::Common {
                        arch,
                        platform: CommonPlatform::WindowsMsvc,
                    },
                    profile: CommonProfile::from_release(release),
                    vmgs_lib: ctx.publish_typed_artifact(pub_vmgs_lib),
                })
                .dep_on(|ctx| flowey_lib_hvlite::build_igvmfilegen::Request {
                    build_params: flowey_lib_hvlite::build_igvmfilegen::IgvmfilegenBuildParams {
                        target: CommonTriple::Common {
                            arch,
                            platform: CommonPlatform::WindowsMsvc,
                        },
                        profile: CommonProfile::from_release(release),
                    },
                    igvmfilegen: ctx.publish_typed_artifact(pub_igvmfilegen),
                })
                .dep_on(|ctx| flowey_lib_hvlite::build_ohcldiag_dev::Request {
                    target: CommonTriple::Common {
                        arch,
                        platform: CommonPlatform::WindowsMsvc,
                    },
                    profile: CommonProfile::from_release(release),
                    ohcldiag_dev: ctx.publish_typed_artifact(pub_ohcldiag_dev),
                })
                .dep_on(|ctx| flowey_lib_hvlite::build_tmk_vmm::Request {
                    target: CommonTriple::Common {
                        arch,
                        platform: CommonPlatform::WindowsMsvc,
                    },
                    unstable_whp: true, // The ARM64 CI runner supports the unstable WHP interface
                    profile: CommonProfile::from_release(release),
                    tmk_vmm: ctx.publish_typed_artifact(pub_tmk_vmm),
                });

            all_jobs.push(job.finish());

            // emit a job for artifacts which _are_ in the VMM tests "hot path"
            let mut job = pipeline
                .new_job(
                    FlowPlatform::Windows,
                    FlowArch::X86_64,
                    format!("build artifacts (for VMM tests) [{arch_tag}-windows]"),
                )
                .gh_set_pool(crate::pipelines_shared::gh_pools::default_gh_hosted(
                    FlowPlatform::Windows,
                ))
                .dep_on(|ctx| {
                    flowey_lib_hvlite::build_openvmm::Request {
                        params: flowey_lib_hvlite::build_openvmm::OpenvmmBuildParams {
                            target: CommonTriple::Common {
                                arch,
                                platform: CommonPlatform::WindowsMsvc,
                            },
                            profile: CommonProfile::from_release(release),
                            // FIXME: this relies on openvmm default features
                            // Our ARM test runners need the latest WHP changes
                            features: if matches!(arch, CommonArch::Aarch64) {
                                [flowey_lib_hvlite::build_openvmm::OpenvmmFeature::UnstableWhp]
                                    .into()
                            } else {
                                [].into()
                            },
                        },
                        openvmm: ctx.publish_typed_artifact(pub_openvmm),
                    }
                })
                .dep_on(|ctx| flowey_lib_hvlite::build_pipette::Request {
                    target: CommonTriple::Common {
                        arch,
                        platform: CommonPlatform::WindowsMsvc,
                    },
                    profile: CommonProfile::from_release(release),
                    pipette: ctx.publish_typed_artifact(pub_pipette_windows),
                });

            // Hang building the windows VMM tests off this big windows job.
            match arch {
                CommonArch::X86_64 => {
                    let pub_vmm_tests_archive_windows_x86 =
                        pub_vmm_tests_archive_windows_x86.take().unwrap();
                    job = job.dep_on(|ctx|
                        flowey_lib_hvlite::build_nextest_vmm_tests::Request {
                        target: CommonTriple::X86_64_WINDOWS_MSVC.as_triple(),
                        profile: CommonProfile::from_release(release),
                        build_mode: flowey_lib_hvlite::build_nextest_vmm_tests::BuildNextestVmmTestsMode::Archive(
                            ctx.publish_typed_artifact(pub_vmm_tests_archive_windows_x86),
                        ),
                    });
                }
                CommonArch::Aarch64 => {
                    let pub_vmm_tests_archive_windows_aarch64 =
                        pub_vmm_tests_archive_windows_aarch64.take().unwrap();
                    job = job.dep_on(|ctx| flowey_lib_hvlite::build_nextest_vmm_tests::Request {
                        target: CommonTriple::AARCH64_WINDOWS_MSVC.as_triple(),
                        profile: CommonProfile::from_release(release),
                        build_mode: flowey_lib_hvlite::build_nextest_vmm_tests::BuildNextestVmmTestsMode::Archive(
                            ctx.publish_typed_artifact(pub_vmm_tests_archive_windows_aarch64),
                        ),
                    });
                }
            }

            all_jobs.push(job.finish());
        }

        // emit linux build machine jobs (without openhcl)
        for arch in [CommonArch::Aarch64, CommonArch::X86_64] {
            let arch_tag = match arch {
                CommonArch::X86_64 => "x64",
                CommonArch::Aarch64 => "aarch64",
            };

            let (pub_openvmm, use_openvmm) =
                pipeline.new_typed_artifact(format!("{arch_tag}-linux-openvmm"));
            let (pub_igvmfilegen, _) =
                pipeline.new_typed_artifact(format!("{arch_tag}-linux-igvmfilegen"));
            let (pub_vmgs_lib, _) =
                pipeline.new_typed_artifact(format!("{arch_tag}-linux-vmgs_lib"));
            let (pub_vmgstool, _) =
                pipeline.new_typed_artifact(format!("{arch_tag}-linux-vmgstool"));
            let (pub_ohcldiag_dev, _) =
                pipeline.new_typed_artifact(format!("{arch_tag}-linux-ohcldiag-dev"));
            let (pub_tmks, use_tmks) = pipeline.new_typed_artifact(format!("{arch_tag}-tmks"));

            // NOTE: the choice to build it as part of this linux job was pretty
            // arbitrary. It could just as well hang off the windows job.
            //
            // At this time though, having it here results in a net-reduction in
            // E2E pipeline times, owing to how the VMM tests artifact dependency
            // graph looks like.
            let (pub_guest_test_uefi, use_guest_test_uefi) =
                pipeline.new_typed_artifact(format!("{arch_tag}-guest_test_uefi"));

            // skim off interesting artifacts required by the VMM tests job
            match arch {
                CommonArch::X86_64 => {
                    vmm_tests_artifacts_linux_x86.use_openvmm = Some(use_openvmm.clone());
                    vmm_tests_artifacts_linux_x86.use_guest_test_uefi =
                        Some(use_guest_test_uefi.clone());
                    vmm_tests_artifacts_windows_x86.use_guest_test_uefi =
                        Some(use_guest_test_uefi.clone());
                    vmm_tests_artifacts_windows_x86.use_tmks = Some(use_tmks.clone());
                    vmm_tests_artifacts_linux_x86.use_tmks = Some(use_tmks.clone());
                }
                CommonArch::Aarch64 => {
                    vmm_tests_artifacts_windows_aarch64.use_guest_test_uefi =
                        Some(use_guest_test_uefi.clone());
                    vmm_tests_artifacts_windows_aarch64.use_tmks = Some(use_tmks.clone());
                }
            }

            let mut job = pipeline
                .new_job(
                    FlowPlatform::Linux(FlowPlatformLinuxDistro::Ubuntu),
                    FlowArch::X86_64,
                    format!("build artifacts [{arch_tag}-linux]"),
                )
                .gh_set_pool(crate::pipelines_shared::gh_pools::default_x86_pool(
                    FlowPlatform::Linux(FlowPlatformLinuxDistro::Ubuntu),
                ))
                .dep_on(|ctx| {
                    flowey_lib_hvlite::build_openvmm::Request {
                        params: flowey_lib_hvlite::build_openvmm::OpenvmmBuildParams {
                            target: CommonTriple::Common {
                                arch,
                                platform: CommonPlatform::LinuxGnu,
                            },
                            profile: CommonProfile::from_release(release),
                            // FIXME: this relies on openvmm default features
                            features: [flowey_lib_hvlite::build_openvmm::OpenvmmFeature::Tpm]
                                .into(),
                        },
                        openvmm: ctx.publish_typed_artifact(pub_openvmm),
                    }
                })
                .dep_on(|ctx| flowey_lib_hvlite::build_vmgstool::Request {
                    target: CommonTriple::Common {
                        arch,
                        platform: CommonPlatform::LinuxGnu,
                    },
                    profile: CommonProfile::from_release(release),
                    with_crypto: true,
                    vmgstool: ctx.publish_typed_artifact(pub_vmgstool),
                })
                .dep_on(|ctx| flowey_lib_hvlite::build_and_test_vmgs_lib::Request {
                    target: CommonTriple::Common {
                        arch,
                        platform: CommonPlatform::LinuxGnu,
                    },
                    profile: CommonProfile::from_release(release),
                    vmgs_lib: ctx.publish_typed_artifact(pub_vmgs_lib),
                })
                .dep_on(|ctx| flowey_lib_hvlite::build_igvmfilegen::Request {
                    build_params: flowey_lib_hvlite::build_igvmfilegen::IgvmfilegenBuildParams {
                        target: CommonTriple::Common {
                            arch,
                            platform: CommonPlatform::LinuxGnu,
                        },
                        profile: CommonProfile::from_release(release),
                    },
                    igvmfilegen: ctx.publish_typed_artifact(pub_igvmfilegen),
                })
                .dep_on(|ctx| flowey_lib_hvlite::build_ohcldiag_dev::Request {
                    target: CommonTriple::Common {
                        arch,
                        platform: CommonPlatform::LinuxGnu,
                    },
                    profile: CommonProfile::from_release(release),
                    ohcldiag_dev: ctx.publish_typed_artifact(pub_ohcldiag_dev),
                })
                .dep_on(|ctx| flowey_lib_hvlite::build_guest_test_uefi::Request {
                    arch,
                    profile: CommonProfile::from_release(release),
                    guest_test_uefi: ctx.publish_typed_artifact(pub_guest_test_uefi),
                })
                .dep_on(|ctx| flowey_lib_hvlite::build_tmks::Request {
                    arch,
                    profile: CommonProfile::from_release(release),
                    tmks: ctx.publish_typed_artifact(pub_tmks),
                });

            // Hang building the linux VMM tests off this big linux job.
            //
            // No ARM64 VMM tests yet
            if matches!(arch, CommonArch::X86_64) {
                let pub_vmm_tests_archive_linux_x86 =
                    pub_vmm_tests_archive_linux_x86.take().unwrap();
                job = job.dep_on(|ctx| flowey_lib_hvlite::build_nextest_vmm_tests::Request {
                    target: CommonTriple::X86_64_LINUX_GNU.as_triple(),
                    profile: CommonProfile::from_release(release),
                    build_mode: flowey_lib_hvlite::build_nextest_vmm_tests::BuildNextestVmmTestsMode::Archive(
                        ctx.publish_typed_artifact(pub_vmm_tests_archive_linux_x86),
                    ),
                });
            }

            all_jobs.push(job.finish());
        }

        // emit openhcl build job
        for arch in [CommonArch::Aarch64, CommonArch::X86_64] {
            let arch_tag = match arch {
                CommonArch::X86_64 => "x64",
                CommonArch::Aarch64 => "aarch64",
            };

            let openvmm_hcl_profile = if release {
                OpenvmmHclBuildProfile::OpenvmmHclShip
            } else {
                OpenvmmHclBuildProfile::Debug
            };

            let (pub_openhcl_igvm, use_openhcl_igvm) =
                pipeline.new_artifact(format!("{arch_tag}-openhcl-igvm"));
            let (pub_openhcl_igvm_extras, _use_openhcl_igvm_extras) =
                pipeline.new_artifact(format!("{arch_tag}-openhcl-igvm-extras"));

            let (pub_openhcl_baseline, _use_openhcl_baseline) =
                if matches!(config, PipelineConfig::Ci) {
                    let (p, u) = pipeline.new_artifact(format!("{arch_tag}-openhcl-baseline"));
                    (Some(p), Some(u))
                } else {
                    (None, None)
                };

            // also build pipette musl on this job, as until we land the
            // refactor that allows building musl without the full openhcl
            // toolchain, it would require pulling in all the openhcl
            // toolchain deps...
            let (pub_pipette_linux_musl, use_pipette_linux_musl) =
                pipeline.new_typed_artifact(format!("{arch_tag}-linux-musl-pipette"));

            let (pub_tmk_vmm, use_tmk_vmm) =
                pipeline.new_typed_artifact(format!("{arch_tag}-linux-musl-tmk_vmm"));

            // skim off interesting artifacts required by the VMM tests job
            match arch {
                CommonArch::X86_64 => {
                    vmm_tests_artifacts_windows_x86.use_openhcl_igvm_files =
                        Some(use_openhcl_igvm.clone());
                    vmm_tests_artifacts_windows_x86.use_pipette_linux_musl =
                        Some(use_pipette_linux_musl.clone());
                    vmm_tests_artifacts_linux_x86.use_pipette_linux_musl =
                        Some(use_pipette_linux_musl.clone());
                    vmm_tests_artifacts_linux_x86.use_tmk_vmm = Some(use_tmk_vmm.clone());
                    vmm_tests_artifacts_windows_x86.use_tmk_vmm_linux_musl =
                        Some(use_tmk_vmm.clone());
                }
                CommonArch::Aarch64 => {
                    vmm_tests_artifacts_windows_aarch64.use_openhcl_igvm_files =
                        Some(use_openhcl_igvm.clone());
                    vmm_tests_artifacts_windows_aarch64.use_pipette_linux_musl =
                        Some(use_pipette_linux_musl.clone());
                    vmm_tests_artifacts_windows_aarch64.use_tmk_vmm_linux_musl =
                        Some(use_tmk_vmm.clone());
                }
            }
            let igvm_recipes = match arch {
                CommonArch::X86_64 => vec![
                    OpenhclIgvmRecipe::X64,
                    OpenhclIgvmRecipe::X64Devkern,
                    OpenhclIgvmRecipe::X64TestLinuxDirect,
                    OpenhclIgvmRecipe::X64TestLinuxDirectDevkern,
                    OpenhclIgvmRecipe::X64Cvm,
                ],
                CommonArch::Aarch64 => {
                    vec![
                        OpenhclIgvmRecipe::Aarch64,
                        OpenhclIgvmRecipe::Aarch64Devkern,
                    ]
                }
            };

            let job = pipeline
                .new_job(
                    FlowPlatform::Linux(FlowPlatformLinuxDistro::Ubuntu),
                    FlowArch::X86_64,
                    format!("build openhcl [{arch_tag}-linux]"),
                )
                .gh_set_pool(crate::pipelines_shared::gh_pools::default_x86_pool(
                    FlowPlatform::Linux(FlowPlatformLinuxDistro::Ubuntu),
                ))
                .dep_on(|ctx| {
                    let publish_baseline_artifact = pub_openhcl_baseline
                        .map(|baseline_artifact| ctx.publish_artifact(baseline_artifact));

                    flowey_lib_hvlite::_jobs::build_and_publish_openhcl_igvm_from_recipe::Params {
                        igvm_files: igvm_recipes
                            .clone()
                            .into_iter()
                            .map(|recipe| OpenhclIgvmBuildParams {
                                profile: openvmm_hcl_profile,
                                recipe,
                                custom_target: Some(CommonTriple::Custom(openhcl_musl_target(
                                    arch,
                                ))),
                            })
                            .collect(),
                        artifact_dir_openhcl_igvm: ctx.publish_artifact(pub_openhcl_igvm),
                        artifact_dir_openhcl_igvm_extras: ctx
                            .publish_artifact(pub_openhcl_igvm_extras),
                        artifact_openhcl_verify_size_baseline: publish_baseline_artifact,
                        done: ctx.new_done_handle(),
                    }
                })
                .dep_on(|ctx| flowey_lib_hvlite::build_pipette::Request {
                    target: CommonTriple::Common {
                        arch,
                        platform: CommonPlatform::LinuxMusl,
                    },
                    profile: CommonProfile::from_release(release),
                    pipette: ctx.publish_typed_artifact(pub_pipette_linux_musl),
                })
                .dep_on(|ctx| flowey_lib_hvlite::build_tmk_vmm::Request {
                    target: CommonTriple::Common {
                        arch,
                        platform: CommonPlatform::LinuxMusl,
                    },
                    profile: CommonProfile::from_release(release),
                    unstable_whp: false,
                    tmk_vmm: ctx.publish_typed_artifact(pub_tmk_vmm),
                });

            all_jobs.push(job.finish());

            if arch == CommonArch::X86_64 && matches!(config, PipelineConfig::Pr) {
                let job = pipeline
                    .new_job(
                        FlowPlatform::Linux(FlowPlatformLinuxDistro::Ubuntu),
                        FlowArch::X86_64,
                        format!("verify openhcl binary size [{}]", arch_tag),
                    )
                    .gh_set_pool(crate::pipelines_shared::gh_pools::default_x86_pool(
                        FlowPlatform::Linux(FlowPlatformLinuxDistro::Ubuntu),
                    ))
                    .dep_on(
                        |ctx| flowey_lib_hvlite::_jobs::check_openvmm_hcl_size::Request {
                            target: CommonTriple::Common {
                                arch,
                                platform: CommonPlatform::LinuxMusl,
                            },
                            done: ctx.new_done_handle(),
                            pipeline_name: "openvmm-ci.yaml".into(),
                        },
                    )
                    .finish();
                all_jobs.push(job);
            }
        }

        // Emit clippy + unit-test jobs
        //
        // The only reason we bundle clippy and unit-tests together is to avoid
        // requiring another build agent.
        struct ClippyUnitTestJobParams<'a> {
            platform: FlowPlatform,
            arch: FlowArch,
            gh_pool: GhRunner,
            clippy_targets: Option<(&'a str, &'a [(Triple, bool)])>,
            unit_test_target: Option<(&'a str, Triple)>,
        }

        for ClippyUnitTestJobParams {
            platform,
            arch,
            gh_pool,
            clippy_targets,
            unit_test_target,
        } in [
            ClippyUnitTestJobParams {
                platform: FlowPlatform::Windows,
                arch: FlowArch::X86_64,
                gh_pool: crate::pipelines_shared::gh_pools::windows_amd_self_hosted(),
                clippy_targets: Some((
                    "windows",
                    &[
                        (target_lexicon::triple!("x86_64-pc-windows-msvc"), false),
                        (target_lexicon::triple!("aarch64-pc-windows-msvc"), false),
                    ],
                )),
                unit_test_target: Some((
                    "x64-windows",
                    target_lexicon::triple!("x86_64-pc-windows-msvc"),
                )),
            },
            ClippyUnitTestJobParams {
                platform: FlowPlatform::Linux(FlowPlatformLinuxDistro::Ubuntu),
                arch: FlowArch::X86_64,
                gh_pool: crate::pipelines_shared::gh_pools::linux_self_hosted(),
                clippy_targets: Some((
                    "linux, macos",
                    &[
                        (target_lexicon::triple!("x86_64-unknown-linux-gnu"), false),
                        (target_lexicon::triple!("aarch64-unknown-linux-gnu"), false),
                        (target_lexicon::triple!("aarch64-apple-darwin"), false),
                    ],
                )),
                unit_test_target: Some((
                    "x64-linux",
                    target_lexicon::triple!("x86_64-unknown-linux-gnu"),
                )),
            },
            ClippyUnitTestJobParams {
                platform: FlowPlatform::Linux(FlowPlatformLinuxDistro::Ubuntu),
                arch: FlowArch::X86_64,
                gh_pool: crate::pipelines_shared::gh_pools::linux_self_hosted(),
                clippy_targets: Some((
                    "linux-musl, misc nostd",
                    &[
                        (openhcl_musl_target(CommonArch::X86_64), true),
                        (openhcl_musl_target(CommonArch::Aarch64), true),
                    ],
                )),
                unit_test_target: Some(("x64-linux-musl", openhcl_musl_target(CommonArch::X86_64))),
            },
            ClippyUnitTestJobParams {
                platform: FlowPlatform::Windows,
                arch: FlowArch::Aarch64,
                gh_pool: crate::pipelines_shared::gh_pools::windows_arm_self_hosted_baremetal(),
                clippy_targets: None,
                unit_test_target: Some((
                    "aarch64-windows",
                    target_lexicon::triple!("aarch64-pc-windows-msvc"),
                )),
            },
        ] {
            let mut job_name = Vec::new();
            if let Some((label, _)) = &clippy_targets {
                job_name.push(format!("clippy [{label}]"));
            }
            if let Some((label, _)) = &unit_test_target {
                job_name.push(format!("unit tests [{label}]"));
            }
            let job_name = job_name.join(", ");

            let unit_test_target = unit_test_target.map(|(label, target)| {
                let test_label = format!("{label}-unit-tests");
                let pub_unit_test_junit_xml = if matches!(backend_hint, PipelineBackendHint::Local)
                {
                    Some(pipeline.new_artifact(&test_label).0)
                } else {
                    None
                };
                (test_label, target, pub_unit_test_junit_xml)
            });

            let mut clippy_unit_test_job = pipeline
                .new_job(platform, arch, job_name)
                .gh_set_pool(gh_pool);

            if let Some((_, targets)) = clippy_targets {
                for (target, also_check_misc_nostd_crates) in targets {
                    clippy_unit_test_job = clippy_unit_test_job.dep_on(|ctx| {
                        flowey_lib_hvlite::_jobs::check_clippy::Request {
                            target: target.clone(),
                            profile: CommonProfile::from_release(release),
                            done: ctx.new_done_handle(),
                            also_check_misc_nostd_crates: *also_check_misc_nostd_crates,
                        }
                    });
                }
            }

            if let Some((test_label, target, pub_unit_test_junit_xml)) = unit_test_target {
                clippy_unit_test_job = clippy_unit_test_job
                    .dep_on(|ctx| {
                        flowey_lib_hvlite::_jobs::build_and_run_nextest_unit_tests::Params {
                            junit_test_label: test_label,
                            nextest_profile:
                                flowey_lib_hvlite::run_cargo_nextest_run::NextestProfile::Ci,
                            fail_job_on_test_fail: true,
                            target: target.clone(),
                            profile: CommonProfile::from_release(release),
                            unstable_panic_abort_tests: None,
                            artifact_dir: pub_unit_test_junit_xml.map(|x| ctx.publish_artifact(x)),
                            done: ctx.new_done_handle(),
                        }
                    })
                    .dep_on(
                        |ctx| flowey_lib_hvlite::_jobs::build_and_run_doc_tests::Params {
                            target,
                            profile: CommonProfile::from_release(release),
                            done: ctx.new_done_handle(),
                        },
                    );
            }

            all_jobs.push(clippy_unit_test_job.finish());
        }

        let vmm_tests_artifacts_windows_intel_x86 = vmm_tests_artifacts_windows_x86
            .clone()
            .finish()
            .map_err(|missing| {
                anyhow::anyhow!("missing required windows-intel vmm_tests artifact: {missing}")
            })?;
        let vmm_tests_artifacts_windows_intel_tdx_x86 = vmm_tests_artifacts_windows_x86
            .clone()
            .finish()
            .map_err(|missing| {
                anyhow::anyhow!("missing required windows-tdx vmm_tests artifact: {missing}")
            })?;
        let vmm_tests_artifacts_windows_amd_x86 = vmm_tests_artifacts_windows_x86
            .finish()
            .map_err(|missing| {
                anyhow::anyhow!("missing required windows-amd vmm_tests artifact: {missing}")
            })?;
        let vmm_tests_artifacts_linux_x86 =
            vmm_tests_artifacts_linux_x86.finish().map_err(|missing| {
                anyhow::anyhow!("missing required linux vmm_tests artifact: {missing}")
            })?;
        let vmm_tests_artifacts_windows_aarch64 = vmm_tests_artifacts_windows_aarch64
            .finish()
            .map_err(|missing| {
                anyhow::anyhow!("missing required windows-aarch64 vmm_tests artifact: {missing}")
            })?;

        // Emit VMM tests runner jobs
        struct VmmTestJobParams<'a> {
            platform: FlowPlatform,
            arch: FlowArch,
            gh_pool: GhRunner,
            label: &'a str,
            target: CommonTriple,
            resolve_vmm_tests_artifacts: vmm_tests_artifact_builders::ResolveVmmTestsDepArtifacts,
            nextest_filter_expr: String,
            vhds: Vec<KnownVhd>,
            isos: Vec<KnownIso>,
        }

        // standard VM-based CI machines should be able to run all tests except
        // those that require special hardware features (tdx) or need to be run
        // on a baremetal host (hyper-v vbs doesn't seem to work nested)
        let standard_filter = "all() & !test(tdx) & !(test(vbs) & test(hyperv))".to_string();
        let standard_x64_vhds = vec![
            KnownVhd::FreeBsd13_2,
            KnownVhd::Gen1WindowsDataCenterCore2022,
            KnownVhd::Gen2WindowsDataCenterCore2022,
            KnownVhd::Ubuntu2204Server,
            KnownVhd::VmgsWithBootEntry,
        ];
        let standard_x64_isos = vec![KnownIso::FreeBsd13_2];

        for VmmTestJobParams {
            platform,
            arch,
            gh_pool,
            label,
            target,
            resolve_vmm_tests_artifacts,
            nextest_filter_expr,
            vhds,
            isos,
        } in [
            VmmTestJobParams {
                platform: FlowPlatform::Windows,
                arch: FlowArch::X86_64,
                gh_pool: crate::pipelines_shared::gh_pools::windows_intel_self_hosted_largedisk(),
                label: "x64-windows-intel",
                target: CommonTriple::X86_64_WINDOWS_MSVC,
                resolve_vmm_tests_artifacts: vmm_tests_artifacts_windows_intel_x86,
                nextest_filter_expr: standard_filter.clone(),
                vhds: standard_x64_vhds.clone(),
                isos: standard_x64_isos.clone(),
            },
            VmmTestJobParams {
                platform: FlowPlatform::Windows,
                arch: FlowArch::X86_64,
                gh_pool: crate::pipelines_shared::gh_pools::windows_tdx_self_hosted_baremetal(),
                label: "x64-windows-intel-tdx",
                target: CommonTriple::X86_64_WINDOWS_MSVC,
                resolve_vmm_tests_artifacts: vmm_tests_artifacts_windows_intel_tdx_x86,
                nextest_filter_expr: "test(tdx) + (test(vbs) & test(hyperv))".to_string(),
                vhds: vec![KnownVhd::Gen2WindowsDataCenterCore2025],
                isos: vec![],
            },
            VmmTestJobParams {
                platform: FlowPlatform::Windows,
                arch: FlowArch::X86_64,
                gh_pool: crate::pipelines_shared::gh_pools::windows_amd_self_hosted_largedisk(),
                label: "x64-windows-amd",
                target: CommonTriple::X86_64_WINDOWS_MSVC,
                resolve_vmm_tests_artifacts: vmm_tests_artifacts_windows_amd_x86,
                nextest_filter_expr: standard_filter.clone(),
                vhds: standard_x64_vhds.clone(),
                isos: standard_x64_isos.clone(),
            },
            VmmTestJobParams {
                platform: FlowPlatform::Linux(FlowPlatformLinuxDistro::Ubuntu),
                arch: FlowArch::X86_64,
                gh_pool: crate::pipelines_shared::gh_pools::linux_self_hosted(),
                label: "x64-linux",
                target: CommonTriple::X86_64_LINUX_GNU,
                resolve_vmm_tests_artifacts: vmm_tests_artifacts_linux_x86,
                // - OpenHCL is not supported on KVM
                // - No legal way to obtain gen1 pcat blobs on non-msft linux machines
                nextest_filter_expr: format!(
                    "{standard_filter} & !test(openhcl) & !test(pcat_x64)"
                ),
                vhds: standard_x64_vhds,
                isos: standard_x64_isos,
            },
            VmmTestJobParams {
                platform: FlowPlatform::Windows,
                arch: FlowArch::Aarch64,
                gh_pool: crate::pipelines_shared::gh_pools::windows_arm_self_hosted_baremetal(),
                label: "aarch64-windows",
                target: CommonTriple::AARCH64_WINDOWS_MSVC,
                resolve_vmm_tests_artifacts: vmm_tests_artifacts_windows_aarch64,
                nextest_filter_expr: "all()".to_string(),
                vhds: vec![
                    KnownVhd::Ubuntu2404ServerAarch64,
                    KnownVhd::VmgsWithBootEntry,
                ],
                isos: vec![],
            },
        ] {
            let test_label = format!("{label}-vmm-tests");

            let pub_vmm_tests_results = if matches!(backend_hint, PipelineBackendHint::Local) {
                Some(pipeline.new_artifact(&test_label).0)
            } else {
                None
            };

            let use_vmm_tests_archive = match target {
                CommonTriple::X86_64_WINDOWS_MSVC => &use_vmm_tests_archive_windows_x86,
                CommonTriple::X86_64_LINUX_GNU => &use_vmm_tests_archive_linux_x86,
                CommonTriple::AARCH64_WINDOWS_MSVC => &use_vmm_tests_archive_windows_aarch64,
                _ => unreachable!(),
            };

            let mut vmm_tests_run_job = pipeline
                .new_job(platform, arch, format!("run vmm-tests [{label}]"))
                .gh_set_pool(gh_pool)
                .dep_on(|ctx| {
                    flowey_lib_hvlite::_jobs::consume_and_test_nextest_vmm_tests_archive::Params {
                        junit_test_label: test_label,
                        nextest_vmm_tests_archive: ctx.use_typed_artifact(use_vmm_tests_archive),
                        target: target.as_triple(),
                        nextest_profile:
                            flowey_lib_hvlite::run_cargo_nextest_run::NextestProfile::Ci,
                        nextest_filter_expr: Some(nextest_filter_expr),
                        dep_artifact_dirs: resolve_vmm_tests_artifacts(ctx),
                        vhds,
                        isos,
                        fail_job_on_test_fail: true,
                        artifact_dir: pub_vmm_tests_results.map(|x| ctx.publish_artifact(x)),
                        done: ctx.new_done_handle(),
                    }
                });

            if let Some(vmm_tests_disk_cache_dir) = vmm_tests_disk_cache_dir.clone() {
                vmm_tests_run_job = vmm_tests_run_job.dep_on(|_| {
                    flowey_lib_hvlite::download_openvmm_vmm_tests_vhds::Request::CustomCacheDir(
                        vmm_tests_disk_cache_dir,
                    )
                })
            }

            all_jobs.push(vmm_tests_run_job.finish());
        }

        // test the flowey local backend by running cargo xflowey build-igvm on x64
        {
            let job = pipeline
                .new_job(
                    FlowPlatform::Linux(FlowPlatformLinuxDistro::Ubuntu),
                    FlowArch::X86_64,
                    "test flowey local backend",
                )
                .gh_set_pool(crate::pipelines_shared::gh_pools::default_x86_pool(
                    FlowPlatform::Linux(FlowPlatformLinuxDistro::Ubuntu),
                ))
                .dep_on(
                    |ctx| flowey_lib_hvlite::_jobs::test_local_flowey_build_igvm::Request {
                        base_recipe: OpenhclIgvmRecipe::X64,
                        done: ctx.new_done_handle(),
                    },
                )
                .finish();
            all_jobs.push(job);
        }

        if matches!(config, PipelineConfig::Pr) {
            // Add a job that depends on all others as a workaround for
            // https://github.com/orgs/community/discussions/12395.
            //
            // This workaround then itself requires _another_ workaround, requiring
            // the use of `gh_dangerous_override_if`, and some additional custom job
            // logic, to deal with https://github.com/actions/runner/issues/2566.
            //
            // TODO: Add a way for this job to skip flowey setup and become a true
            // no-op.
            let all_good_job = pipeline
                .new_job(
                    FlowPlatform::Linux(FlowPlatformLinuxDistro::Ubuntu),
                    FlowArch::X86_64,
                    "openvmm checkin gates",
                )
                .gh_set_pool(crate::pipelines_shared::gh_pools::default_gh_hosted(
                    FlowPlatform::Linux(FlowPlatformLinuxDistro::Ubuntu),
                ))
                // always run this job, regardless whether or not any previous jobs failed
                .gh_dangerous_override_if("always() && github.event.pull_request.draft == false")
                .gh_dangerous_global_env_var("ANY_JOBS_FAILED", "${{ contains(needs.*.result, 'cancelled') || contains(needs.*.result, 'failure') }}")
                .dep_on(|ctx| flowey_lib_hvlite::_jobs::all_good_job::Params {
                    did_fail_env_var: "ANY_JOBS_FAILED".into(),
                    done: ctx.new_done_handle(),
                })
                .finish();

            for job in all_jobs.iter() {
                pipeline.non_artifact_dep(&all_good_job, job);
            }
        }

        Ok(pipeline)
    }
}

/// Utility builders which make it easy to "skim off" artifacts required by VMM
/// test execution from other pipeline jobs.
//
// FUTURE: if we end up having a _lot_ of VMM test jobs, this would be the sort
// of thing that would really benefit from a derive macro.
mod vmm_tests_artifact_builders {
    use flowey::pipeline::prelude::*;
    use flowey_lib_hvlite::_jobs::consume_and_test_nextest_vmm_tests_archive::VmmTestsDepArtifacts;
    use flowey_lib_hvlite::build_guest_test_uefi::GuestTestUefiOutput;
    use flowey_lib_hvlite::build_openvmm::OpenvmmOutput;
    use flowey_lib_hvlite::build_pipette::PipetteOutput;
    use flowey_lib_hvlite::build_tmk_vmm::TmkVmmOutput;
    use flowey_lib_hvlite::build_tmks::TmksOutput;

    pub type ResolveVmmTestsDepArtifacts =
        Box<dyn Fn(&mut PipelineJobCtx<'_>) -> VmmTestsDepArtifacts>;

    #[derive(Default)]
    pub struct VmmTestsArtifactsBuilderLinuxX86 {
        // windows build machine
        pub use_pipette_windows: Option<UseTypedArtifact<PipetteOutput>>,
        pub use_tmk_vmm: Option<UseTypedArtifact<TmkVmmOutput>>,
        // linux build machine
        pub use_openvmm: Option<UseTypedArtifact<OpenvmmOutput>>,
        pub use_pipette_linux_musl: Option<UseTypedArtifact<PipetteOutput>>,
        // any machine
        pub use_guest_test_uefi: Option<UseTypedArtifact<GuestTestUefiOutput>>,
        pub use_tmks: Option<UseTypedArtifact<TmksOutput>>,
    }

    impl VmmTestsArtifactsBuilderLinuxX86 {
        pub fn finish(self) -> Result<ResolveVmmTestsDepArtifacts, &'static str> {
            let VmmTestsArtifactsBuilderLinuxX86 {
                use_openvmm,
                use_guest_test_uefi,
                use_pipette_windows,
                use_pipette_linux_musl,
                use_tmk_vmm,
                use_tmks,
            } = self;

            let use_guest_test_uefi = use_guest_test_uefi.ok_or("guest_test_uefi")?;
            let use_openvmm = use_openvmm.ok_or("openvmm")?;
            let use_pipette_linux_musl = use_pipette_linux_musl.ok_or("pipette_linux_musl")?;
            let use_pipette_windows = use_pipette_windows.ok_or("pipette_windows")?;
            let use_tmk_vmm = use_tmk_vmm.ok_or("tmk_vmm")?;
            let use_tmks = use_tmks.ok_or("tmks")?;

            Ok(Box::new(move |ctx| VmmTestsDepArtifacts {
                openvmm: Some(ctx.use_typed_artifact(&use_openvmm)),
                pipette_windows: Some(ctx.use_typed_artifact(&use_pipette_windows)),
                pipette_linux_musl: Some(ctx.use_typed_artifact(&use_pipette_linux_musl)),
                guest_test_uefi: Some(ctx.use_typed_artifact(&use_guest_test_uefi)),
                tmk_vmm: Some(ctx.use_typed_artifact(&use_tmk_vmm)),
                tmks: Some(ctx.use_typed_artifact(&use_tmks)),
                // not currently required, since OpenHCL tests cannot be run on OpenVMM on linux
                artifact_dir_openhcl_igvm_files: None,
                tmk_vmm_linux_musl: None,
            }))
        }
    }

    #[derive(Default, Clone)]
    pub struct VmmTestsArtifactsBuilderWindowsX86 {
        // windows build machine
        pub use_openvmm: Option<UseTypedArtifact<OpenvmmOutput>>,
        pub use_pipette_windows: Option<UseTypedArtifact<PipetteOutput>>,
        pub use_tmk_vmm: Option<UseTypedArtifact<TmkVmmOutput>>,
        // linux build machine
        pub use_openhcl_igvm_files: Option<UseArtifact>,
        pub use_pipette_linux_musl: Option<UseTypedArtifact<PipetteOutput>>,
        pub use_tmk_vmm_linux_musl: Option<UseTypedArtifact<TmkVmmOutput>>,
        // any machine
        pub use_guest_test_uefi: Option<UseTypedArtifact<GuestTestUefiOutput>>,
        pub use_tmks: Option<UseTypedArtifact<TmksOutput>>,
    }

    impl VmmTestsArtifactsBuilderWindowsX86 {
        pub fn finish(self) -> Result<ResolveVmmTestsDepArtifacts, &'static str> {
            let VmmTestsArtifactsBuilderWindowsX86 {
                use_openvmm,
                use_pipette_windows,
                use_pipette_linux_musl,
                use_guest_test_uefi,
                use_openhcl_igvm_files,
                use_tmk_vmm,
                use_tmk_vmm_linux_musl,
                use_tmks,
            } = self;

            let use_openvmm = use_openvmm.ok_or("openvmm")?;
            let use_pipette_windows = use_pipette_windows.ok_or("pipette_windows")?;
            let use_pipette_linux_musl = use_pipette_linux_musl.ok_or("pipette_linux_musl")?;
            let use_guest_test_uefi = use_guest_test_uefi.ok_or("guest_test_uefi")?;
            let use_openhcl_igvm_files = use_openhcl_igvm_files.ok_or("openhcl_igvm_files")?;
            let use_tmk_vmm = use_tmk_vmm.ok_or("tmk_vmm")?;
            let use_tmk_vmm_linux_musl = use_tmk_vmm_linux_musl.ok_or("tmk_vmm_linux_musl")?;
            let use_tmks = use_tmks.ok_or("tmks")?;

            Ok(Box::new(move |ctx| VmmTestsDepArtifacts {
                openvmm: Some(ctx.use_typed_artifact(&use_openvmm)),
                pipette_windows: Some(ctx.use_typed_artifact(&use_pipette_windows)),
                pipette_linux_musl: Some(ctx.use_typed_artifact(&use_pipette_linux_musl)),
                guest_test_uefi: Some(ctx.use_typed_artifact(&use_guest_test_uefi)),
                artifact_dir_openhcl_igvm_files: Some(ctx.use_artifact(&use_openhcl_igvm_files)),
                tmk_vmm: Some(ctx.use_typed_artifact(&use_tmk_vmm)),
                tmk_vmm_linux_musl: Some(ctx.use_typed_artifact(&use_tmk_vmm_linux_musl)),
                tmks: Some(ctx.use_typed_artifact(&use_tmks)),
            }))
        }
    }

    #[derive(Default, Clone)]
    pub struct VmmTestsArtifactsBuilderWindowsAarch64 {
        // windows build machine
        pub use_openvmm: Option<UseTypedArtifact<OpenvmmOutput>>,
        pub use_pipette_windows: Option<UseTypedArtifact<PipetteOutput>>,
        pub use_tmk_vmm: Option<UseTypedArtifact<TmkVmmOutput>>,
        // linux build machine
        pub use_openhcl_igvm_files: Option<UseArtifact>,
        pub use_pipette_linux_musl: Option<UseTypedArtifact<PipetteOutput>>,
        pub use_tmk_vmm_linux_musl: Option<UseTypedArtifact<TmkVmmOutput>>,
        // any machine
        pub use_guest_test_uefi: Option<UseTypedArtifact<GuestTestUefiOutput>>,
        pub use_tmks: Option<UseTypedArtifact<TmksOutput>>,
    }

    impl VmmTestsArtifactsBuilderWindowsAarch64 {
        pub fn finish(self) -> Result<ResolveVmmTestsDepArtifacts, &'static str> {
            let VmmTestsArtifactsBuilderWindowsAarch64 {
                use_openvmm,
                use_pipette_windows,
                use_pipette_linux_musl,
                use_guest_test_uefi,
                use_openhcl_igvm_files,
                use_tmk_vmm,
                use_tmk_vmm_linux_musl,
                use_tmks,
            } = self;

            let use_openvmm = use_openvmm.ok_or("openvmm")?;
            let use_pipette_windows = use_pipette_windows.ok_or("pipette_windows")?;
            let use_pipette_linux_musl = use_pipette_linux_musl.ok_or("pipette_linux_musl")?;
            let use_guest_test_uefi = use_guest_test_uefi.ok_or("guest_test_uefi")?;
            let use_openhcl_igvm_files = use_openhcl_igvm_files.ok_or("openhcl_igvm_files")?;
            let use_tmk_vmm = use_tmk_vmm.ok_or("tmk_vmm")?;
            let use_tmk_vmm_linux_musl = use_tmk_vmm_linux_musl.ok_or("tmk_vmm_linux_musl")?;
            let use_tmks = use_tmks.ok_or("tmks")?;

            Ok(Box::new(move |ctx| VmmTestsDepArtifacts {
                openvmm: Some(ctx.use_typed_artifact(&use_openvmm)),
                pipette_windows: Some(ctx.use_typed_artifact(&use_pipette_windows)),
                pipette_linux_musl: Some(ctx.use_typed_artifact(&use_pipette_linux_musl)),
                guest_test_uefi: Some(ctx.use_typed_artifact(&use_guest_test_uefi)),
                artifact_dir_openhcl_igvm_files: Some(ctx.use_artifact(&use_openhcl_igvm_files)),
                tmk_vmm: Some(ctx.use_typed_artifact(&use_tmk_vmm)),
                tmk_vmm_linux_musl: Some(ctx.use_typed_artifact(&use_tmk_vmm_linux_musl)),
                tmks: Some(ctx.use_typed_artifact(&use_tmks)),
            }))
        }
    }
}
