// Copyright (C) Microsoft Corporation. All rights reserved.

//! Publish JUnit test results.
//!
//! On supported platforms, this will hook into the backend's native JUnit
//! handling (if available).
//!
//! On all platforms, will publish all provided XMLs into a single "test
//! results" artifact (if provided).

use flowey::node::prelude::*;

flowey_request! {
    pub enum Request {
        /// Register a XML file to be published
        Register {
            /// Path to a junit.xml file
            ///
            /// HACK: this is an optional since `flowey` doesn't (yet?) have any way
            /// to perform conditional-requests, and there are instances where nodes
            /// will only conditionally output JUnit XML.
            ///
            /// To keep making forward progress, I've tweaked this node to accept an
            /// optional... but this ain't great.
            junit_xml: ReadVar<Option<PathBuf>>,
            /// Brief string used when publishing the test.
            test_label: String,
            /// Side-effect confirming that the publish has succeeded
            done: WriteVar<SideEffect>,
        },
        /// (Optional) publish all registered JUnit XML files to the provided dir
        PublishToArtifact(ReadVar<PathBuf>, WriteVar<SideEffect>),
    }
}

new_flow_node!(struct Node);

impl FlowNode for Node {
    type Request = Request;

    fn imports(_ctx: &mut ImportCtx<'_>) {}

    fn emit(requests: Vec<Self::Request>, ctx: &mut NodeCtx<'_>) -> anyhow::Result<()> {
        let mut xmls = Vec::new();
        let mut artifact_dir = None;

        for req in requests {
            match req {
                Request::Register {
                    junit_xml,
                    test_label,
                    done,
                } => xmls.push((junit_xml, test_label, done)),
                Request::PublishToArtifact(a, b) => same_across_all_reqs_backing_var(
                    "PublishToArtifact",
                    &mut artifact_dir,
                    (a, b),
                )?,
            }
        }

        let xmls = xmls;
        let artifact_dir = artifact_dir;

        let did_copy = if let Some((artifact_dir, done)) = artifact_dir {
            let se = ctx.emit_rust_step("copy JUnit test results to artifact dir", |ctx| {
                done.claim(ctx);
                let artifact_dir = artifact_dir.claim(ctx);
                let xmls = xmls
                    .iter()
                    .map(|(junit_xml, label, _done)| (junit_xml.clone().claim(ctx), label.clone()))
                    .collect::<Vec<_>>();
                |rt| {
                    let artifact_dir = rt.read(artifact_dir);

                    for (idx, (path, label)) in xmls.into_iter().enumerate() {
                        let Some(path) = rt.read(path) else {
                            continue;
                        };
                        fs_err::rename(
                            path,
                            artifact_dir
                                .join(format!("results_{idx}_{}.xml", label.replace(' ', "_"))),
                        )?;
                    }

                    Ok(())
                }
            });
            Some(se)
        } else {
            None
        };

        if matches!(ctx.backend(), FlowBackend::Ado) {
            for (junit_xml, label, done) in xmls {
                let has_path = junit_xml.map(ctx, |p| p.is_some());
                let path = junit_xml.map(ctx, |p| {
                    p.map(|p| p.absolute().expect("TEMP").display().to_string())
                        .unwrap_or_default()
                });
                ctx.emit_ado_step_with_condition(
                    format!("publish JUnit test results: {label}"),
                    has_path,
                    |ctx| {
                        done.claim(ctx);
                        did_copy.clone().claim(ctx);
                        let path = path.claim(ctx);
                        move |rt| {
                            let path = rt.get_var(path).as_raw_var_name();
                            format!(
                                r#"
                                    - task: PublishTestResults@2
                                      inputs:
                                        testResultsFormat: 'JUnit'
                                        testResultsFiles: '$({path})'
                                        testRunTitle: '{label}'
                                "#
                            )
                        }
                    },
                );
            }
        } else {
            let all_done = xmls.into_iter().map(|(_, _, done)| done);
            ctx.emit_side_effect_step(did_copy, all_done);
        }

        Ok(())
    }
}
