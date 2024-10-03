// Copyright (C) Microsoft Corporation. All rights reserved.

//! Vmbus channel implementations using async.

#![warn(missing_docs)]
#![forbid(unsafe_code)]

pub mod async_dgram;
mod core;
pub mod pipe;
pub mod queue;
