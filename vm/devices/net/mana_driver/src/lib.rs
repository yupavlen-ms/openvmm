// Copyright (C) Microsoft Corporation. All rights reserved.

//! A user-mode driver for MANA (Microsoft Azure Network Adapter) devices.

#![warn(missing_docs)]

mod bnic_driver;
mod gdma_driver;
pub mod mana;
pub mod queues;
mod resources;
mod store_fence;
#[cfg(test)]
mod tests;
