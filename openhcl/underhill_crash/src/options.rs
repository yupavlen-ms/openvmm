// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Argument struct for underhill crash capturing.

#![warn(missing_docs)]

use std::ffi::OsString;
use std::time::Duration;

// We've made our own parser here instead of using something like clap in order
// to save on compiled file size. We don't need all the features a crate can provide.
/// underhill crash environment settings and command-line parameters.
/// The order of command-line arguments is expected to be: {pid} {tid} {signal} {command line}
pub struct Options {
    /// PID of the process
    pub pid: u32,
    /// TID of the faulted thread
    pub tid: u32,
    /// Signal
    pub sig: u32,
    /// Command line the process was started with
    pub comm: String,

    /// Be verbose
    pub verbose: bool,
    /// Timeout
    pub timeout: Duration,
}

impl Options {
    pub(crate) fn parse() -> Self {
        let mut args = std::env::args_os();

        // Skip our own filename.
        args.next();

        let parse_number = |arg: Option<OsString>| {
            arg.and_then(|x| x.to_string_lossy().parse().ok())
                .expect(Self::USAGE)
        };

        let pid = parse_number(args.next());
        let tid = parse_number(args.next());
        let sig = parse_number(args.next());
        let comm = args
            .next()
            .expect(Self::USAGE)
            .to_string_lossy()
            .into_owned();

        if args.next().is_some() {
            panic!("{}", Self::USAGE);
        }

        let timeout = Duration::from_secs(
            std::env::var("UNDERHILL_CRASH_TIMEOUT")
                .unwrap_or_else(|_| "15".into())
                .parse()
                .expect(Self::USAGE),
        );

        let verbose_var = std::env::var("UNDERHILL_CRASH_VERBOSE").unwrap_or_default();
        let verbose = verbose_var == "1" || verbose_var.eq_ignore_ascii_case("true");

        Self {
            pid,
            tid,
            sig,
            comm,

            verbose,
            timeout,
        }
    }

    const USAGE: &'static str = "Usage: {pid} {tid} {signal} {command line}
        Environment Variables:
        \tUNDERHILL_CRASH_TIMEOUT - Timeout duration in seconds, default 15
        \tUNDERHILL_CRASH_VERBOSE - Be verbose, default false";
}
