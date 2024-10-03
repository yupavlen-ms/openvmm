// Copyright (C) Microsoft Corporation. All rights reserved.

//! Serial port backends based on Unix sockets and Windows named pipes.

pub mod unix;
#[cfg(windows)]
pub mod windows;
