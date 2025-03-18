// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Encapsulates the logic of invoking `cargo doc`, taking into account
//! bits of "global" configuration and dependency management, such as setting
//! global cargo flags (e.g: --verbose, --locked), ensuring base Rust
//! dependencies are installed, etc...

use flowey::node::prelude::*;
use std::collections::BTreeMap;

#[derive(Serialize, Deserialize)]
pub struct CargoDocCommands {
    cmds: Vec<Vec<String>>,
    cargo_work_dir: PathBuf,
    cargo_out_dir: PathBuf,
}

impl CargoDocCommands {
    /// Execute the doc command(s), returning a path to the built docs
    /// directory.
    pub fn run(self, sh: &xshell::Shell) -> anyhow::Result<PathBuf> {
        self.run_with(sh, |x| x)
    }

    /// Execute the doc command(s), returning path(s) to the built artifact.
    ///
    /// Unlike `run`, this method allows tweaking the build command prior to
    /// running it (e.g: to add env vars, change the working directory where the
    /// artifacts will be placed, etc...).
    pub fn run_with(
        self,
        sh: &xshell::Shell,
        f: impl Fn(xshell::Cmd<'_>) -> xshell::Cmd<'_>,
    ) -> anyhow::Result<PathBuf> {
        let Self {
            cmds,
            cargo_work_dir,
            cargo_out_dir,
        } = self;

        let out_dir = sh.current_dir();
        sh.change_dir(cargo_work_dir);

        for mut cmd in cmds {
            let argv0 = cmd.remove(0);
            let cmd = xshell::cmd!(sh, "{argv0} {cmd...}");
            let cmd = f(cmd);
            cmd.run()?;
        }

        let final_dir = out_dir.join("cargo-doc-out");
        fs_err::rename(cargo_out_dir, &final_dir)?;
        Ok(final_dir)
    }
}

/// Packages that can be documented
#[derive(Serialize, Deserialize)]
pub enum DocPackageKind {
    /// Document an entire workspace workspace (with exclusions)
    Workspace { exclude: Vec<String> },
    /// Document a specific crate.
    Crate(String),
    /// Document a specific no_std crate.
    ///
    /// This is its own variant, as a single `cargo doc` command has issues
    /// documenting mixed `std` and `no_std` crates.
    NoStdCrate(String),
}

/// The "what and how" of packages to documents
#[derive(Serialize, Deserialize)]
pub struct DocPackage {
    /// The thing being documented.
    pub kind: DocPackageKind,
    /// Whether to document non-workspace dependencies (i.e: pass `--no-deps`)
    pub no_deps: bool,
    /// Whether to document private items (i.e: pass `--document-private-items`)
    pub document_private_items: bool,
}

flowey_request! {
    pub struct Request {
        pub in_folder: ReadVar<PathBuf>,
        /// Targets to include in the generated docs.
        pub packages: Vec<DocPackage>,
        /// What target-triple things should get documented with.
        pub target_triple: target_lexicon::Triple,
        pub cargo_cmd: WriteVar<CargoDocCommands>,
    }
}

#[derive(Default)]
struct ResolvedDocPackages {
    // where each (bool, bool) represents (no_deps, document_private_items)
    workspace: Option<(bool, bool)>,
    exclude: Vec<String>,
    crates: BTreeMap<(bool, bool), Vec<String>>,
    crates_no_std: BTreeMap<(bool, bool), Vec<String>>,
}

new_flow_node!(struct Node);

impl FlowNode for Node {
    type Request = Request;

    fn imports(ctx: &mut ImportCtx<'_>) {
        ctx.import::<crate::cfg_cargo_common_flags::Node>();
        ctx.import::<crate::install_rust::Node>();
    }

    fn emit(requests: Vec<Self::Request>, ctx: &mut NodeCtx<'_>) -> anyhow::Result<()> {
        let rust_toolchain = ctx.reqv(crate::install_rust::Request::GetRustupToolchain);
        let flags = ctx.reqv(crate::cfg_cargo_common_flags::Request::GetFlags);

        for Request {
            in_folder,
            packages,
            target_triple,
            cargo_cmd,
        } in requests
        {
            ctx.req(crate::install_rust::Request::InstallTargetTriple(
                target_triple.clone(),
            ));

            // figure out what cargo commands we'll need to invoke
            let mut targets = ResolvedDocPackages::default();
            for DocPackage {
                kind,
                no_deps,
                document_private_items,
            } in packages
            {
                match kind {
                    DocPackageKind::Workspace { exclude } => {
                        if targets.workspace.is_some() {
                            anyhow::bail!("cannot pass Workspace variant multiple times")
                        }
                        targets.exclude.extend(exclude);
                        targets.workspace = Some((no_deps, document_private_items))
                    }
                    DocPackageKind::Crate(name) => targets
                        .crates
                        .entry((no_deps, document_private_items))
                        .or_default()
                        .push(name),
                    DocPackageKind::NoStdCrate(name) => targets
                        .crates_no_std
                        .entry((no_deps, document_private_items))
                        .or_default()
                        .push(name),
                }
            }

            let doc_targets = targets;

            ctx.emit_rust_step("construct cargo doc command", |ctx| {
                let rust_toolchain = rust_toolchain.clone().claim(ctx);
                let flags = flags.clone().claim(ctx);
                let in_folder = in_folder.claim(ctx);
                let write_doc_cmd = cargo_cmd.claim(ctx);

                move |rt| {
                    let rust_toolchain = rt.read(rust_toolchain);
                    let flags = rt.read(flags);
                    let in_folder = rt.read(in_folder);

                    let crate::cfg_cargo_common_flags::Flags { locked, verbose } = flags;

                    let mut cmds = Vec::new();
                    let ResolvedDocPackages {
                        workspace,
                        exclude,
                        mut crates,
                        crates_no_std,
                    } = doc_targets;

                    let base_cmd = |no_deps: bool, document_private_items: bool| -> Vec<String> {
                        let mut v = Vec::new();
                        v.push("cargo".into());
                        if let Some(rust_toolchain) = &rust_toolchain {
                            v.push(format!("+{rust_toolchain}"))
                        }
                        v.push("doc".into());
                        v.push("--target".into());
                        v.push(target_triple.to_string());
                        if locked {
                            v.push("--locked".into());
                        }
                        if verbose {
                            v.push("--verbose".into());
                        }
                        if no_deps {
                            v.push("--no-deps".into());
                        }
                        if document_private_items {
                            v.push("--document-private-items".into())
                        }
                        v
                    };

                    // first command to run should be the workspace-level
                    // command (if one was provided)
                    if let Some((no_deps, document_private_items)) = workspace {
                        // subsume crates with the same options
                        crates.remove(&(no_deps, document_private_items));

                        let mut v = base_cmd(no_deps, document_private_items);

                        v.push("--workspace".into());

                        for crates_no_std in crates_no_std.values() {
                            for c in crates_no_std.iter().chain(exclude.iter()) {
                                v.push("--exclude".into());
                                v.push(c.into())
                            }
                        }

                        cmds.push(v);
                    }

                    // subsequently: document any specific std crates
                    for ((no_deps, document_private_items), crates) in crates {
                        let mut v = base_cmd(no_deps, document_private_items);

                        for c in crates {
                            v.push("-p".into());
                            v.push(c);
                        }

                        cmds.push(v)
                    }

                    // lastly: document any no_std crates
                    for ((no_deps, document_private_items), crates) in crates_no_std {
                        let mut v = base_cmd(no_deps, document_private_items);

                        for c in crates {
                            v.push("-p".into());
                            v.push(c);
                        }

                        cmds.push(v)
                    }

                    let cargo_out_dir = {
                        // DEVNOTE: this is a _pragmatic_ implementation of this
                        // logic, and is written with the undersatnding that
                        // there are undoubtedly many "edge-cases" that may
                        // result in the final target directory changing.
                        //
                        // One possible way to make this handling more robust
                        // would be to start using `--message-format=json` when
                        // invoking `cargo`, and then parsing the machine
                        // readable output in order to obtain the output
                        // artifact path _after_ the compilation has succeeded.
                        if let Ok(dir) = std::env::var("CARGO_TARGET_DIR") {
                            PathBuf::from(dir)
                        } else {
                            in_folder.join("target")
                        }
                    }
                    .join(target_triple.to_string())
                    .join("doc");

                    let cmd = CargoDocCommands {
                        cmds,
                        cargo_work_dir: in_folder.clone(),
                        cargo_out_dir,
                    };

                    rt.write(write_doc_cmd, &cmd);

                    Ok(())
                }
            });
        }

        Ok(())
    }
}
