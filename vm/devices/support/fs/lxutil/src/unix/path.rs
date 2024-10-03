// Copyright (C) Microsoft Corporation. All rights reserved.

use std::borrow::Cow;
use std::ffi::OsStr;
use std::os::unix::prelude::*;
use std::path::Path;

// No-op implementation of path_from_lx for Unix.
pub fn path_from_lx(path: &[u8]) -> lx::Result<Cow<'_, Path>> {
    Ok(Cow::Borrowed(OsStr::from_bytes(path).as_ref()))
}
