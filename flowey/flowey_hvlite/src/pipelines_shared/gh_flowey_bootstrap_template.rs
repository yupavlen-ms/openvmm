// Copyright (C) Microsoft Corporation. All rights reserved.

//! See [`get_template`]

use flowey::node::prelude::GhContextVar;

/// Get our internal flowey bootstrap template.
///
/// See [`Pipeline::gh_set_flowey_bootstrap_template`]
///
/// [`Pipeline::gh_set_flowey_bootstrap_template`]:
///     flowey::pipeline::prelude::Pipeline::gh_set_flowey_bootstrap_template
pub fn get_template(
    client_id: &GhContextVar,
    tenant_id: &GhContextVar,
    subscription_id: &GhContextVar,
) -> String {
    // to be clear: these replaces are totally custom to this particular
    // bootstrap template. flowey knows nothing of these replacements.
    let template = include_str!("gh_flowey_bootstrap_template.yml").to_string();

    template
        .replace(
            "{{OPENVMM_CLIENT_ID}}",
            &format!("${{{{ {} }}}}", client_id.as_raw_var_name()),
        )
        .replace(
            "{{OPENVMM_TENANT_ID}}",
            &format!("${{{{ {} }}}}", tenant_id.as_raw_var_name()),
        )
        .replace(
            "{{OPENVMM_SUBSCRIPTION_ID}}",
            &format!("${{{{ {} }}}}", subscription_id.as_raw_var_name()),
        )
}
