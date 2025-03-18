// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Implementation of submission and completion queues.

use super::spec;
use crate::driver::save_restore::CompletionQueueSavedState;
use crate::driver::save_restore::SubmissionQueueSavedState;
use crate::registers::DeviceRegisters;
use inspect::Inspect;
use safeatomic::AtomicSliceOps;
use std::sync::atomic::AtomicU64;
use std::sync::atomic::Ordering::Acquire;
use std::sync::atomic::Ordering::Relaxed;
use user_driver::DeviceBacking;
use user_driver::memory::MemoryBlock;

#[derive(Inspect)]
pub(crate) struct SubmissionQueue {
    sqid: u16,
    head: u32,
    tail: u32,
    committed_tail: u32,
    len: u32,
    #[inspect(skip)]
    mem: MemoryBlock,
}

#[derive(Debug)]
pub(crate) struct QueueFull;

impl SubmissionQueue {
    pub fn new(sqid: u16, len: u16, mem: MemoryBlock) -> Self {
        Self {
            sqid,
            head: 0,
            tail: 0,
            committed_tail: 0,
            len: len.into(),
            mem,
        }
    }

    pub fn id(&self) -> u16 {
        self.sqid
    }

    pub fn update_head(&mut self, head: u16) {
        let head = head as u32;
        assert!(head < self.len);
        self.head = head;
    }

    pub fn is_full(&self) -> bool {
        advance(self.tail, self.len) == self.head
    }

    pub fn write(&mut self, command: spec::Command) -> Result<(), QueueFull> {
        let next_tail = advance(self.tail, self.len);
        if next_tail == self.head {
            return Err(QueueFull);
        }
        self.mem
            .write_obj(self.tail as usize * size_of_val(&command), &command);
        self.tail = next_tail;
        Ok(())
    }

    pub fn commit<T: DeviceBacking>(&mut self, region: &DeviceRegisters<T>) {
        if self.tail != self.committed_tail {
            safe_intrinsics::store_fence();
            region.doorbell(self.sqid, false, self.tail);
            self.committed_tail = self.tail;
        }
    }

    /// Saves queue data for servicing.
    pub fn save(&self) -> SubmissionQueueSavedState {
        tracing::info!("YSP: SubmissionQueue::save qid={} head={} tail={}/{}", self.sqid, self.head, self.tail, self.committed_tail);
        SubmissionQueueSavedState {
            sqid: self.sqid,
            head: self.head,
            tail: self.tail,
            committed_tail: self.committed_tail,
            len: self.len,
        }
    }

    /// Restores queue data after servicing.
    pub fn restore(
        mem: MemoryBlock,
        saved_state: &SubmissionQueueSavedState,
    ) -> anyhow::Result<Self> {
        tracing::info!("YSP: SubmissionQueue::restore qid={} head={} tail={}/{}", saved_state.sqid, saved_state.head, saved_state.tail, saved_state.committed_tail);
        let SubmissionQueueSavedState {
            sqid,
            head,
            tail,
            committed_tail,
            len,
        } = saved_state;
        Ok(Self {
            sqid: *sqid,
            head: *head,
            tail: *tail,
            committed_tail: *committed_tail,
            len: *len,
            mem,
        })
    }
}

#[derive(Inspect)]
pub(crate) struct CompletionQueue {
    cqid: u16,
    head: u32,
    committed_head: u32,
    /// Queue size in entries.
    len: u32,
    phase: bool,
    #[inspect(skip)]
    mem: MemoryBlock,
}

impl CompletionQueue {
    pub fn new(cqid: u16, len: u16, mem: MemoryBlock) -> CompletionQueue {
        Self {
            cqid,
            head: 0,
            committed_head: 0,
            len: len.into(),
            phase: true,
            mem,
        }
    }

    pub fn _id(&self) -> u16 {
        self.cqid
    }

    pub fn read(&mut self) -> Option<spec::Completion> {
        let completion_mem = self.mem.as_slice()
            [self.head as usize * size_of::<spec::Completion>()..]
            [..size_of::<spec::Completion>() * 2]
            .as_atomic_slice::<AtomicU64>()
            .unwrap();

        // Check the phase bit, using an acquire read to ensure the rest of the
        // completion is read with or after the phase bit.
        let high = completion_mem[1].load(Acquire);
        let status = spec::CompletionStatus::from((high >> 48) as u16);
        if status.phase() != self.phase {
            return None;
        }
        let low = completion_mem[0].load(Relaxed);
        let completion: spec::Completion = zerocopy::transmute!([low, high]);
        self.head += 1;
        if self.head == self.len {
            self.head = 0;
            self.phase = !self.phase;
        }
        Some(completion)
    }

    pub fn commit<T: DeviceBacking>(&mut self, registers: &DeviceRegisters<T>) {
        if self.head != self.committed_head {
            safe_intrinsics::store_fence();
            registers.doorbell(self.cqid, true, self.head);
            self.committed_head = self.head;
        }
    }

    /// Saves queue data for servicing.
    pub fn save(&self) -> CompletionQueueSavedState {
        tracing::info!("YSP: CompletionQueue::save qid={} head={}/{} tag={}", self.cqid, self.head, self.committed_head, self.phase);
        CompletionQueueSavedState {
            cqid: self.cqid,
            head: self.head,
            committed_head: self.committed_head,
            len: self.len,
            phase: self.phase,
        }
    }

    /// Restores queue data after servicing.
    pub fn restore(
        mem: MemoryBlock,
        saved_state: &CompletionQueueSavedState,
    ) -> anyhow::Result<Self> {
        tracing::info!("YSP: CompletionQueue::restore qid={} head={}/{} tag={}", saved_state.cqid, saved_state.head, saved_state.committed_head, saved_state.phase);
        // YSP: FIXME: Debug code
        let mut checker: [u8; 8] = [0; 8];
        mem.read_at(0, checker.as_mut_slice());
        tracing::info!(
            "YSP: read [{} {} {} {} {} {} {} {}]",
            checker[0],
            checker[1],
            checker[2],
            checker[3],
            checker[4],
            checker[5],
            checker[6],
            checker[7],
        );
        let CompletionQueueSavedState {
            cqid,
            head,
            committed_head,
            len,
            phase,
        } = saved_state;

        Ok(Self {
            cqid: *cqid,
            head: *head,
            committed_head: *committed_head,
            len: *len,
            phase: *phase,
            mem,
        })
    }
}

fn advance(n: u32, l: u32) -> u32 {
    if n + 1 < l { n + 1 } else { 0 }
}
