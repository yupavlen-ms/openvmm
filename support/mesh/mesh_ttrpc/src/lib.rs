// Copyright (C) Microsoft Corporation. All rights reserved.

//! ttrpc client and server implementation.
//!
//! ttrpc is a low-overhead, high-density local RPC interface used for
//! containerd to communicate with its shims and plugins. It uses the same
//! payload format as GRPC but a much simpler transport format.

#![warn(missing_docs)]

#[cfg(test)]
extern crate self as mesh_ttrpc;

mod client;
mod message;
mod rpc;
mod server;
pub mod service;

pub use client::Client;
pub use server::Server;
