// Copyright (C) Microsoft Corporation. All rights reserved.

//! Download various pre-built `openvmm-deps` dependencies.

use flowey::node::prelude::*;
use std::collections::BTreeMap;

#[derive(Serialize, Deserialize, Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum OpenvmmDepsArch {
    X86_64,
    Aarch64,
}

flowey_request! {
    pub enum Request {
        /// Specify version of the github release to pull from
        Version(String),
        GetLinuxTestKernel(OpenvmmDepsArch, WriteVar<PathBuf>),
        GetLinuxTestInitrd(OpenvmmDepsArch, WriteVar<PathBuf>),
        GetOpenhclCpioDbgrd(OpenvmmDepsArch, WriteVar<PathBuf>),
        GetOpenhclCpioShell(OpenvmmDepsArch, WriteVar<PathBuf>),
        GetOpenhclSysroot(OpenvmmDepsArch, WriteVar<PathBuf>),
    }
}

new_flow_node!(struct Node);

impl FlowNode for Node {
    type Request = Request;

    fn imports(ctx: &mut ImportCtx<'_>) {
        ctx.import::<flowey_lib_common::install_apt_pkg::Node>();
        ctx.import::<flowey_lib_common::download_gh_release::Node>();
    }

    fn emit(requests: Vec<Self::Request>, ctx: &mut NodeCtx<'_>) -> anyhow::Result<()> {
        let mut version = None;
        let mut linux_test_kernel: BTreeMap<_, Vec<_>> = BTreeMap::new();
        let mut linux_test_initrd: BTreeMap<_, Vec<_>> = BTreeMap::new();
        let mut openhcl_cpio_dbgrd: BTreeMap<_, Vec<_>> = BTreeMap::new();
        let mut openhcl_cpio_shell: BTreeMap<_, Vec<_>> = BTreeMap::new();
        let mut openhcl_sysroot: BTreeMap<_, Vec<_>> = BTreeMap::new();

        for req in requests {
            match req {
                Request::Version(v) => same_across_all_reqs("Version", &mut version, v)?,

                Request::GetLinuxTestKernel(arch, var) => {
                    linux_test_kernel.entry(arch).or_default().push(var)
                }
                Request::GetLinuxTestInitrd(arch, var) => {
                    linux_test_initrd.entry(arch).or_default().push(var)
                }
                Request::GetOpenhclCpioDbgrd(arch, var) => {
                    openhcl_cpio_dbgrd.entry(arch).or_default().push(var)
                }
                Request::GetOpenhclCpioShell(arch, var) => {
                    openhcl_cpio_shell.entry(arch).or_default().push(var)
                }
                Request::GetOpenhclSysroot(arch, var) => {
                    openhcl_sysroot.entry(arch).or_default().push(var)
                }
            }
        }

        let version = version.ok_or(anyhow::anyhow!("Missing essential request: Version"))?;

        // -- end of req processing -- //

        if linux_test_initrd.is_empty()
            && linux_test_kernel.is_empty()
            && openhcl_cpio_dbgrd.is_empty()
            && openhcl_cpio_shell.is_empty()
            && openhcl_sysroot.is_empty()
        {
            return Ok(());
        }

        let extract_tar_bz2_deps =
            flowey_lib_common::_util::extract::extract_tar_bz2_if_new_deps(ctx);

        let file_name = format!("openvmm-deps.{version}.tar.bz2");

        // DEVNOTE: until we find time to resolve microsoft/openvmm-deps#15,
        // there is a single chunky archive file containing all these deps.
        //
        // This is unfortunate, as you end up downloading a bunch of stuff you
        // don't use...
        let openvmm_deps_tar_bz2 = ctx.reqv(|v| flowey_lib_common::download_gh_release::Request {
            repo_owner: "microsoft".into(),
            repo_name: "openvmm-deps".into(),
            tag: version.clone(),
            file_name: file_name.clone(),
            path: v,
        });

        ctx.emit_rust_step("unpack openvmm-deps archive", |ctx| {
            let extract_tar_bz2_deps = extract_tar_bz2_deps.claim(ctx);
            let openvmm_deps_tar_bz2 = openvmm_deps_tar_bz2.claim(ctx);

            let linux_test_kernel = linux_test_kernel.claim(ctx);
            let linux_test_initrd = linux_test_initrd.claim(ctx);
            let openhcl_cpio_dbgrd = openhcl_cpio_dbgrd.claim(ctx);
            let openhcl_cpio_shell = openhcl_cpio_shell.claim(ctx);
            let openhcl_sysroot = openhcl_sysroot.claim(ctx);
            move |rt| {
                let openvmm_deps_tar_bz2 = rt.read(openvmm_deps_tar_bz2);

                let extract_dir = flowey_lib_common::_util::extract::extract_tar_bz2_if_new(
                    rt,
                    extract_tar_bz2_deps,
                    &openvmm_deps_tar_bz2,
                    // NOTE: until we have different files for various
                    // artifacts, the only unique id for the package is the
                    // version.
                    &version,
                )?;

                let base_dir = move |arch| {
                    extract_dir.join(match arch {
                        OpenvmmDepsArch::X86_64 => "x86_64",
                        OpenvmmDepsArch::Aarch64 => "aarch64",
                    })
                };

                let kernel_path = |arch| {
                    base_dir(OpenvmmDepsArch::X86_64).join(match arch {
                        OpenvmmDepsArch::X86_64 => "vmlinux",
                        OpenvmmDepsArch::Aarch64 => "Image",
                    })
                };

                for (arch, vars) in linux_test_kernel {
                    let path = kernel_path(arch);
                    rt.write_all(vars, &path)
                }

                for (arch, vars) in linux_test_initrd {
                    let path = base_dir(arch).join("initrd");
                    rt.write_all(vars, &path)
                }

                for (arch, vars) in openhcl_cpio_dbgrd {
                    let path = base_dir(arch).join("dbgrd.cpio.gz");
                    rt.write_all(vars, &path)
                }

                for (arch, vars) in openhcl_cpio_shell {
                    let path = base_dir(arch).join("shell.cpio.gz");
                    rt.write_all(vars, &path)
                }

                for (arch, vars) in openhcl_sysroot {
                    let path = base_dir(arch).join("sysroot.tar.gz");
                    rt.write_all(vars, &path)
                }

                Ok(())
            }
        });

        Ok(())
    }
}
