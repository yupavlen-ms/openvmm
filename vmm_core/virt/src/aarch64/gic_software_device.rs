// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! VPCI device implementation for GIC-based VMs.

use crate::irqcon::ControlGic;
use pci_core::msi::MsiControl;
use pci_core::msi::MsiInterruptTarget;
use std::ops::Range;
use std::sync::Arc;
use thiserror::Error;
use vmcore::vpci_msi::MapVpciInterrupt;
use vmcore::vpci_msi::MsiAddressData;
use vmcore::vpci_msi::RegisterInterruptError;

pub struct GicSoftwareDevice {
    irqcon: Arc<dyn ControlGic>,
}

impl GicSoftwareDevice {
    pub fn new(irqcon: Arc<dyn ControlGic>) -> Self {
        Self { irqcon }
    }
}

#[derive(Debug, Error)]
enum GicInterruptError {
    #[error("invalid vector count")]
    InvalidVectorCount,
    #[error("invalid vector")]
    InvalidVector,
}

const SPI_RANGE: Range<u32> = 32..1020;

impl MapVpciInterrupt for GicSoftwareDevice {
    async fn register_interrupt(
        &self,
        vector_count: u32,
        params: &vmcore::vpci_msi::VpciInterruptParameters<'_>,
    ) -> Result<MsiAddressData, RegisterInterruptError> {
        if !vector_count.is_power_of_two() {
            return Err(RegisterInterruptError::new(
                GicInterruptError::InvalidVectorCount,
            ));
        }
        if params.vector < SPI_RANGE.start
            || params.vector.saturating_add(vector_count) > SPI_RANGE.end
        {
            return Err(RegisterInterruptError::new(
                GicInterruptError::InvalidVector,
            ));
        }
        Ok(MsiAddressData {
            address: 0,
            data: params.vector,
        })
    }

    async fn unregister_interrupt(&self, address: u64, data: u32) {
        let _ = (address, data);
    }
}

impl MsiInterruptTarget for GicSoftwareDevice {
    fn new_interrupt(&self) -> Box<dyn MsiControl> {
        let irqcon = self.irqcon.clone();
        Box::new(move |_address, data| {
            if SPI_RANGE.contains(&data) {
                irqcon.set_spi_irq(data, true);
            }
        })
    }
}
