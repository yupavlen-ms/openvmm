// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! MigTD stub.

use super::tdx::tdx_wait_for_request;

pub fn migtd_wait_for_request() {
    let _ = tdx_wait_for_request();
}
