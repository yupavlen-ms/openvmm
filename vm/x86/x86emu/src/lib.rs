// Copyright (C) Microsoft Corporation. All rights reserved.

#![forbid(unsafe_code)]

mod cpu;
mod emulator;
mod registers;

pub use cpu::Cpu;
pub use emulator::fast_path;
pub use emulator::Emulator;
pub use emulator::Error;
pub use emulator::MAX_REP_LOOPS;
pub use registers::CpuState;
