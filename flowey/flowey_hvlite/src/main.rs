// Copyright (C) Microsoft Corporation. All rights reserved.

//! Flowey pipelines used by the OpenVMM project

fn main() {
    flowey_cli::flowey_main::<flowey_hvlite::pipelines::OpenvmmPipelines>(
        "flowey_hvlite",
        &flowey_hvlite::repo_root(),
    )
}
