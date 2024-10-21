// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Ensure the OpenHCL sysroot is extracted into the correct "magic directory"
//! set by the project-level `[env]` table in `.cargo/config.toml`

use crate::download_openvmm_deps::OpenvmmDepsArch;
use flowey::node::prelude::*;
use std::collections::BTreeMap;

new_flow_node!(struct Node);

#[derive(Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub enum OpenvmmSysrootArch {
    Aarch64,
    X64,
}

flowey_request! {
    pub struct Request {
        pub arch: OpenvmmSysrootArch,
        pub path: WriteVar<PathBuf>,
    }
}

impl FlowNode for Node {
    type Request = Request;

    fn imports(ctx: &mut ImportCtx<'_>) {
        ctx.import::<crate::cfg_openvmm_magicpath::Node>();
        ctx.import::<crate::download_openvmm_deps::Node>();
    }

    fn emit(requests: Vec<Self::Request>, ctx: &mut NodeCtx<'_>) -> anyhow::Result<()> {
        let mut sysroot_arch: BTreeMap<_, Vec<_>> = BTreeMap::new();

        for Request { arch, path } in requests {
            sysroot_arch.entry(arch).or_default().push(path)
        }

        let sysroot_arch = sysroot_arch;

        // -- end of req processing -- //

        if !matches!(ctx.platform(), FlowPlatform::Linux) {
            anyhow::bail!("step only available on linux systems");
        }

        let openvmm_magicpath = ctx.reqv(crate::cfg_openvmm_magicpath::Request);

        for (arch, out_vars) in sysroot_arch {
            let openhcl_sysroot = ctx.reqv(|v| {
                crate::download_openvmm_deps::Request::GetOpenhclSysroot(
                    match arch {
                        OpenvmmSysrootArch::Aarch64 => OpenvmmDepsArch::Aarch64,
                        OpenvmmSysrootArch::X64 => OpenvmmDepsArch::X86_64,
                    },
                    v,
                )
            });

            let openvmm_magicpath = openvmm_magicpath.clone();

            ctx.emit_rust_step(format!("symlink {arch:?} openhcl sysroot"), move |ctx| {
                let openhcl_sysroot = openhcl_sysroot.claim(ctx);
                let openvmm_magicpath = openvmm_magicpath.claim(ctx);
                let requests = out_vars.claim(ctx);

                move |rt| {
                    let openhcl_sysroot = rt.read(openhcl_sysroot);

                    let extracted_sysroot_path =
                        rt.read(openvmm_magicpath)
                            .join("extracted")
                            .join(match arch {
                                OpenvmmSysrootArch::Aarch64 => "aarch64-sysroot",
                                OpenvmmSysrootArch::X64 => "x86_64-sysroot",
                            });
                    fs_err::create_dir_all(extracted_sysroot_path.parent().unwrap())?;
                    fs_err::remove_dir_all(&extracted_sysroot_path)?;

                    #[cfg(unix)]
                    let symlink = |orig, link| fs_err::os::unix::fs::symlink(orig, link);
                    #[cfg(windows)]
                    let symlink = |orig, link| fs_err::os::windows::fs::symlink_dir(orig, link);

                    symlink(openhcl_sysroot, &extracted_sysroot_path)?;

                    for var in requests {
                        rt.write(var, &extracted_sysroot_path.absolute()?)
                    }

                    Ok(())
                }
            });
        }

        Ok(())
    }
}
