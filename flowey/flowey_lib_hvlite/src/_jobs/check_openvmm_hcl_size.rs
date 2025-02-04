// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Compares the size of the OpenHCL binary in the current PR with the size of the binary from the last successful merge to main.

use crate::artifact_openhcl_igvm_from_recipe_extras;
use crate::build_openhcl_igvm_from_recipe;
use crate::build_openhcl_igvm_from_recipe::OpenhclIgvmRecipe;
use crate::build_openvmm_hcl;
use crate::build_openvmm_hcl::OpenvmmHclBuildParams;
use crate::build_openvmm_hcl::OpenvmmHclBuildProfile::OpenvmmHclShip;
use crate::run_cargo_build::common::CommonArch;
use crate::run_cargo_build::common::CommonTriple;
use flowey::node::prelude::*;
use flowey_lib_common::download_gh_artifact;
use flowey_lib_common::gh_workflow_id;
use flowey_lib_common::git_merge_commit;

flowey_request! {
    pub struct Request {
        pub target: CommonTriple,
        pub done: WriteVar<SideEffect>,
        pub pipeline_name: String,
    }
}

new_simple_flow_node!(struct Node);

impl SimpleFlowNode for Node {
    type Request = Request;

    fn imports(ctx: &mut ImportCtx<'_>) {
        ctx.import::<crate::build_xtask::Node>();
        ctx.import::<crate::git_checkout_openvmm_repo::Node>();
        ctx.import::<download_gh_artifact::Node>();
        ctx.import::<git_merge_commit::Node>();
        ctx.import::<gh_workflow_id::Node>();
        ctx.import::<build_openhcl_igvm_from_recipe::Node>();
        ctx.import::<build_openvmm_hcl::Node>();
        ctx.import::<artifact_openhcl_igvm_from_recipe_extras::publish::Node>();
    }

    fn process_request(request: Self::Request, ctx: &mut NodeCtx<'_>) -> anyhow::Result<()> {
        let Request {
            target,
            done,
            pipeline_name,
        } = request;

        let xtask = ctx.reqv(|v| crate::build_xtask::Request {
            target: target.clone(),
            xtask: v,
        });
        let openvmm_repo_path = ctx.reqv(crate::git_checkout_openvmm_repo::req::GetRepoDir);

        let gh_token = ctx.get_gh_context_var().global().token();

        let built_openvmm_hcl = ctx.reqv(|v| build_openvmm_hcl::Request {
            build_params: OpenvmmHclBuildParams {
                target: target.clone(),
                profile: OpenvmmHclShip,
                features: (OpenhclIgvmRecipe::X64)
                    .recipe_details(OpenvmmHclShip)
                    .openvmm_hcl_features,
                no_split_dbg_info: false,
            },
            openvmm_hcl_output: v,
        });

        let file_name = match target.common_arch().unwrap() {
            CommonArch::X86_64 => "x64-openhcl-igvm-extras",
            CommonArch::Aarch64 => "aarch64-openhcl-igvm-extras",
        };

        let merge_commit = ctx.reqv(|v| git_merge_commit::Request {
            repo_path: openvmm_repo_path.clone(),
            merge_commit: v,
            base_branch: "main".into(),
        });

        let merge_run = ctx.reqv(|v| gh_workflow_id::Request {
            repo_path: openvmm_repo_path.clone(),
            github_commit_hash: merge_commit,
            gh_workflow: v,
            pipeline_name,
            gh_token: gh_token.clone(),
        });

        let run_id = merge_run.map(ctx, |r| r.id);
        let merge_head_artifact = ctx.reqv(|old_openhcl| download_gh_artifact::Request {
            repo_owner: "microsoft".into(),
            repo_name: "openvmm".into(),
            file_name: file_name.into(),
            path: old_openhcl,
            run_id,
            gh_token: gh_token.clone(),
        });

        let comparison = ctx.emit_rust_step("binary size comparison", |ctx| {
            let xtask = xtask.claim(ctx);
            let openvmm_repo_path = openvmm_repo_path.claim(ctx);
            let old_openhcl = merge_head_artifact.claim(ctx);
            let new_openhcl = built_openvmm_hcl.claim(ctx);
            let merge_run = merge_run.claim(ctx);

            move |rt| {
                let xtask = match rt.read(xtask) {
                    crate::build_xtask::XtaskOutput::LinuxBin { bin, .. } => bin,
                    crate::build_xtask::XtaskOutput::WindowsBin { exe, .. } => exe,
                };

                let old_openhcl = rt.read(old_openhcl);
                let new_openhcl = rt.read(new_openhcl);
                let merge_run = rt.read(merge_run);

                let arch = target.common_arch().unwrap();

                let old_path = match arch {
                    CommonArch::X86_64 => {
                        old_openhcl.join("x64-openhcl-igvm-extras/openhcl/openhcl")
                    }
                    CommonArch::Aarch64 => old_openhcl.join("openhcl-aarch64/openhcl"),
                };
                let new_path = new_openhcl.bin;

                println!(
                    "comparing HEAD to merge commit {} and workflow {}",
                    merge_run.commit, merge_run.id
                );

                let sh = xshell::Shell::new()?;
                sh.change_dir(rt.read(openvmm_repo_path));
                xshell::cmd!(
                    sh,
                    "{xtask} verify-size --original {old_path} --new {new_path}"
                )
                .run()?;

                Ok(())
            }
        });

        ctx.emit_side_effect_step(vec![comparison], [done]);

        Ok(())
    }
}
