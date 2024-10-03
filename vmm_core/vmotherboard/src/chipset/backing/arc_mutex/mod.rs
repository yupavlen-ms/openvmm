// Copyright (C) Microsoft Corporation. All rights reserved.

//! Infrastructure for wiring up `Arc + Mutex`-backed `ChipsetDevice` instances
//! to the virtual motherboard.

pub mod device;
pub mod pci;
pub mod services;
pub mod state_unit;
