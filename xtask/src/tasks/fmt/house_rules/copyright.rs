// Copyright (C) Microsoft Corporation. All rights reserved.

use anyhow::anyhow;
use fs_err::File;
use std::io::BufRead;
use std::io::BufReader;
use std::io::Write;
use std::path::Path;

pub fn check_copyright(path: &Path, fix: bool) -> anyhow::Result<()> {
    const HEADER: &str = "Copyright (C) Microsoft Corporation. All rights reserved.";
    const HEADER_MIT_FIRST: &str = "Copyright (c) Microsoft Corporation.";
    const HEADER_MIT_SECOND: &str = "Licensed under the MIT License.";

    let ext = path
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or_default();

    if !matches!(ext, "rs" | "c" | "proto" | "toml" | "ts" | "js") {
        return Ok(());
    }

    let f = BufReader::new(File::open(path)?);
    let mut lines = f.lines();
    let first_line = lines.next().unwrap_or(Ok(String::new()))?;
    let second_line = lines.next().unwrap_or(Ok(String::new()))?;
    let third_line = lines.next().unwrap_or(Ok(String::new()))?;
    let mut mit = false;

    let missing_copyright = {
        if first_line.contains(HEADER) {
            // Correct Microsoft copyright.
            false
        } else if first_line.contains(HEADER_MIT_FIRST) && second_line.contains(HEADER_MIT_SECOND) {
            // Some files may be Microsoft copyright with MIT license.
            mit = true;
            false
        } else if first_line.contains("Copyright") && !first_line.contains("Microsoft") {
            // OK, copyright someone else. Ignore this house rule.
            return Ok(());
        } else {
            // Either the wrong Microsoft copyright, or no copyright.
            true
        }
    };

    let missing_blank_line = if mit {
        !third_line.is_empty()
    } else {
        !second_line.is_empty()
    };

    if fix {
        // windows gets touchy if you try and rename files while there are open
        // file handles
        drop(lines);

        if missing_copyright || missing_blank_line {
            let path_fix = &{
                let mut p = path.to_path_buf();
                let ok = p.set_extension(format!("{}.fix", ext));
                assert!(ok);
                p
            };

            let mut f = BufReader::new(File::open(path)?);
            let mut f_fixed = File::create(path_fix)?;

            if missing_copyright {
                let prefix = match ext {
                    "rs" | "c" | "proto" => "//",
                    "toml" => "#",
                    _ => unreachable!(),
                };
                writeln!(f_fixed, "{} {}", prefix, HEADER)?;
                writeln!(f_fixed)?; // also add that missing blank line
            } else if missing_blank_line {
                // copy the valid header from the current file
                let mut s = String::new();
                f.read_line(&mut s)?;
                write!(f_fixed, "{}", s)?;
                // ...but then tack on the blank newline as well
                writeln!(f_fixed)?;
            }

            // copy over the rest of the file contents
            std::io::copy(&mut f, &mut f_fixed)?;

            // windows gets touchy if you try and rename files while there are open
            // file handles
            drop(f);
            drop(f_fixed);

            // ...and then swap the file with the newly fixed file
            fs_err::rename(path_fix, path)?;
        }
    }

    let msg = match (missing_copyright, missing_blank_line) {
        (true, true) => "missing copyright header + subsequent blank line",
        (true, false) => "missing copyright header",
        (false, true) => "missing blank line after copyright header",
        (false, false) => return Ok(()),
    };

    if fix {
        log::info!("fixed {} in {}", msg, path.display());
        Ok(())
    } else {
        Err(anyhow!("{} in {}", msg, path.display()))
    }
}
