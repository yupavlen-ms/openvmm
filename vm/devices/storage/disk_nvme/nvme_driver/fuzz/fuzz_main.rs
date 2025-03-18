// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#![expect(missing_docs)]
#![cfg_attr(all(target_os = "linux", target_env = "gnu"), no_main)]

//! A 2-way fuzzer developed to fuzz the nvme driver from the Guest side with arbitrary driver
//! actions and from the Host side with arbitrary responses from the backend.
mod fuzz_emulated_device;
mod fuzz_nvme_driver;

use crate::fuzz_nvme_driver::FuzzNvmeDriver;

use arbitrary::Arbitrary;
use arbitrary::Unstructured;
use pal_async::DefaultPool;
use parking_lot::Mutex;
use xtask_fuzz::fuzz_target;

// Anything consumed by EmulatedDeviceFuzzer needs to be static because of DeviceBacking trait.
pub static RAW_DATA: Mutex<Vec<u8>> = Mutex::new(Vec::new());

/// Returns an arbitrary data of type T or a NotEnoughData error. Generic type must
/// implement Arbitrary (for any lifetime 'a) and the Sized traits.
pub fn arbitrary_data<T>() -> Result<T, arbitrary::Error>
where
    for<'a> T: Arbitrary<'a> + Sized,
{
    let mut raw_data = RAW_DATA.lock();
    let input = raw_data.split_off(0); // Take all raw_data
    let mut u = Unstructured::new(&input);

    if u.is_empty() {
        return Err(arbitrary::Error::NotEnoughData);
    }

    // If bytes needed is more than remaining bytes it will pad with 0s.
    let arbitrary_type: T = u.arbitrary()?;

    let x = u.take_rest().to_vec();
    *raw_data = x;
    Ok(arbitrary_type)
}

/// Uses the provided input to repeatedly create and execute an arbitrary action on the NvmeDriver.
fn do_fuzz() {
    DefaultPool::run_with(async |driver| {
        let create_fuzzing_driver = FuzzNvmeDriver::new(driver).await;
        if let Err(_e) = create_fuzzing_driver {
            return;
        }

        let mut fuzzing_driver = create_fuzzing_driver.unwrap();

        loop {
            let next_action = fuzzing_driver.execute_arbitrary_action().await;

            // Not enough data
            if let Err(_e) = next_action {
                break;
            }
        }

        fuzzing_driver.shutdown().await;
    });
}

fuzz_target!(|input: Vec<u8>| {
    xtask_fuzz::init_tracing_if_repro();

    {
        let mut raw_data = RAW_DATA.lock();
        *raw_data = input;
    }

    do_fuzz();
});
