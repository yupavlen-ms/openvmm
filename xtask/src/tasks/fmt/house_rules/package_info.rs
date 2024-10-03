// Copyright (C) Microsoft Corporation. All rights reserved.

//! Checks to ensure that the `[package]` sections of Cargo.toml files do not
//! contain `authors` or `version` fields.
//!
//! Eliding the [version][] sets the version to "0.0.0", which is fine. More
//! importantly, it means the module cannot be published to crates.io
//! (equivalent to publish = false), which is what we want for our internal
//! crates. And removing the meaningless version also eliminates more questions
//! from newcomers (does the version field mean anything? do we use it for
//! semver internally?).
//!
//! The [authors][] field is optional, is not really used anywhere anymore, and
//! just creates confusion.
//!
//! [version]:
//!     <https://doc.rust-lang.org/cargo/reference/manifest.html#the-version-field>
//! [authors]:
//!     <https://doc.rust-lang.org/cargo/reference/manifest.html#the-authors-field>

use anyhow::Context;
use std::ffi::OsStr;
use std::path::Path;

pub fn check_package_info(f: &Path, fix: bool) -> anyhow::Result<()> {
    if f.file_name() != Some(OsStr::new("Cargo.toml")) {
        return Ok(());
    }

    let contents = fs_err::read_to_string(f)?;
    let mut parsed = contents.parse::<toml_edit::Document>()?;

    let Some(package) = parsed.get_mut("package") else {
        // workspace root, skip
        return Ok(());
    };

    let package = package
        .as_table_mut()
        .with_context(|| format!("invalid package section in {}", f.display()))?;

    // Note careful use of non-short-circuiting or.
    let invalid = package.remove("authors").is_some() | package.remove("version").is_some();
    if invalid {
        if !fix {
            anyhow::bail!(
                "invalid inclusion of package authors or version in {}",
                f.display()
            );
        }
        fs_err::write(f, parsed.to_string())?;
        log::info!("fixed package section in {}", f.display());
    }

    Ok(())
}
