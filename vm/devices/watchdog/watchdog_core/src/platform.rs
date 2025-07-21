// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Platform abstraction layer for watchdog timer devices.
//!
//! This module defines the interface between generic watchdog device implementations
//! (like UEFI watchdog) and the specific host environment where they run (OpenVMM,
//! OpenHCL, etc). The abstraction allows watchdog devices to remain platform-agnostic
//! while enabling each platform to handle timeouts appropriately - whether that's
//! logging, generating crash dumps, resetting VMs, or sending interrupts.
//!
//! The key traits are:
//! - [`WatchdogCallback`]: Implement this to define custom timeout behavior
//! - [`WatchdogPlatform`]: The interface that watchdog devices use to handle timeouts

use cvm_tracing::CVM_ALLOWED;
use vmcore::non_volatile_store::NonVolatileStore;
use watchdog_vmgs_format::WatchdogVmgsFormatStore;
use watchdog_vmgs_format::WatchdogVmgsFormatStoreError;

/// Trait for responding to watchdog timeouts.
///
/// Implement this trait whenever you want to respond to watchdog timeouts, then pass
/// your instance to add_callback() on the [`WatchdogPlatform`] trait.
#[async_trait::async_trait]
pub trait WatchdogCallback: Send + Sync {
    /// Called when the watchdog timer expires
    async fn on_timeout(&mut self);
}

/// Blanket implementation of [`WatchdogCallback`] for closures.
///
/// This allows you to pass simple closures directly as callbacks without
/// needing to create a struct.
#[async_trait::async_trait]
impl<F> WatchdogCallback for F
where
    F: FnMut() + Send + Sync,
{
    async fn on_timeout(&mut self) {
        self();
    }
}

/// Defines the watchdog platform interface.
#[async_trait::async_trait]
pub trait WatchdogPlatform: Send {
    /// Callback fired when the timer expires.
    async fn on_timeout(&mut self);

    // Check the vmgs store for boot status and clear it.
    async fn read_and_clear_boot_status(&mut self) -> bool;

    /// Add a callback, which executes when the watchdog times out
    fn add_callback(&mut self, callback: Box<dyn WatchdogCallback>);
}

/// A base implementation of [`WatchdogPlatform`], used by OpenVMM and OpenHCL.
pub struct BaseWatchdogPlatform {
    /// Whether the watchdog has timed out or not.
    watchdog_expired: bool,
    /// Callbacks to execute when the watchdog times out.
    callbacks: Vec<Box<dyn WatchdogCallback>>,
    /// The VMGS store used to persist the watchdog status.
    store: WatchdogVmgsFormatStore,
}

impl BaseWatchdogPlatform {
    pub async fn new(
        store: Box<dyn NonVolatileStore>,
    ) -> Result<Self, WatchdogVmgsFormatStoreError> {
        Ok(BaseWatchdogPlatform {
            watchdog_expired: false,
            callbacks: Vec::new(),
            store: WatchdogVmgsFormatStore::new(store).await?,
        })
    }
}

#[async_trait::async_trait]
impl WatchdogPlatform for BaseWatchdogPlatform {
    async fn on_timeout(&mut self) {
        self.watchdog_expired = true;

        // Persist the watchdog status to the VMGS store
        let result = self.store.set_boot_failure().await;
        if let Err(e) = result {
            tracing::error!(
                CVM_ALLOWED,
                error = &e as &dyn std::error::Error,
                "error persisting watchdog status"
            );
        }

        // Invoke all callbacks
        for callback in &mut self.callbacks {
            callback.on_timeout().await;
        }
    }

    async fn read_and_clear_boot_status(&mut self) -> bool {
        let res = self.store.read_and_clear_boot_status().await;
        match res {
            Ok(status) => status,
            Err(e) => {
                tracing::error!(
                    CVM_ALLOWED,
                    error = &e as &dyn std::error::Error,
                    "error reading watchdog status"
                );
                // assume no failure
                false
            }
        }
    }

    fn add_callback(&mut self, callback: Box<dyn WatchdogCallback>) {
        self.callbacks.push(callback);
    }
}
