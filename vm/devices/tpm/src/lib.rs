// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Emulated TPM 2.0 device.
//!
//! This module implements the hardware TPM interface. This includes
//! both the MMIO interface for reading/writing TPM command/reply
//! buffers, as well as the IO Port interface for performing PPI requests and
//! configuring MMIO request/response regions.

#![cfg(feature = "tpm")]

pub mod ak_cert;
pub mod resolver;
mod tpm20proto;
mod tpm_helper;

use self::io_port_interface::PpiOperation;
use self::io_port_interface::TpmIoCommand;
use crate::ak_cert::TpmAkCertType;
use chipset_device::io::IoError;
use chipset_device::io::IoResult;
use chipset_device::mmio::MmioIntercept;
use chipset_device::pio::PortIoIntercept;
use chipset_device::poll_device::PollDevice;
use chipset_device::ChipsetDevice;
use guestmem::GuestMemory;
use inspect::Inspect;
use inspect::InspectMut;
use ms_tpm_20_ref::MsTpm20RefPlatform;
use parking_lot::Mutex;
use std::future::Future;
use std::ops::RangeInclusive;
use std::pin::Pin;
use std::sync::Arc;
use std::task::Poll;
use std::task::Waker;
use thiserror::Error;
use tpm20proto::CommandCodeEnum;
use tpm20proto::ReservedHandle;
use tpm20proto::NV_INDEX_RANGE_BASE_PLATFORM_MANUFACTURER;
use tpm20proto::NV_INDEX_RANGE_BASE_TCG_ASSIGNED;
use tpm20proto::TPM20_HT_PERSISTENT;
use tpm20proto::TPM20_RH_PLATFORM;
use tpm_helper::CommandDebugInfo;
use tpm_helper::TpmCommandError;
use tpm_helper::TpmEngineHelper;
use tpm_helper::TpmHelperError;
use tpm_resources::TpmRegisterLayout;
use vmcore::device_state::ChangeDeviceState;
use vmcore::non_volatile_store::NonVolatileStore;
use vmcore::non_volatile_store::NonVolatileStoreError;
use zerocopy::FromBytes;
use zerocopy::IntoBytes;

pub const TPM_DEVICE_MMIO_REGION_BASE_ADDRESS: u64 = 0xfed40000;
pub const TPM_DEVICE_MMIO_REGION_SIZE: u64 = 0x70;

pub const TPM_DEVICE_IO_PORT_RANGE_BEGIN: u16 = 0x1040;
pub const TPM_DEVICE_IO_PORT_RANGE_END: u16 = 0x1048;

pub const TPM_DEVICE_IO_PORT_CONTROL_OFFSET: u16 = 0;
pub const TPM_DEVICE_IO_PORT_DATA_OFFSET: u16 = 4;

pub const TPM_DEVICE_MMIO_PORT_REGION_BASE_ADDRESS: u64 =
    TPM_DEVICE_MMIO_REGION_BASE_ADDRESS + 0x80;
pub const TPM_DEVICE_MMIO_PORT_CONTROL: u64 =
    TPM_DEVICE_MMIO_PORT_REGION_BASE_ADDRESS + TPM_DEVICE_IO_PORT_CONTROL_OFFSET as u64;
pub const TPM_DEVICE_MMIO_PORT_DATA: u64 =
    TPM_DEVICE_MMIO_PORT_REGION_BASE_ADDRESS + TPM_DEVICE_IO_PORT_DATA_OFFSET as u64;
pub const TPM_DEVICE_MMIO_PORT_REGION_SIZE: u64 = 0x8;

const TPM_PAGE_SIZE: usize = 4096;

const RSA_2K_MODULUS_BITS: u16 = 2048;
const RSA_2K_MODULUS_SIZE: usize = (RSA_2K_MODULUS_BITS / 8) as usize;
const RSA_2K_EXPONENT_SIZE: usize = 3;

const TPM_RSA_SRK_HANDLE: ReservedHandle = ReservedHandle::new(TPM20_HT_PERSISTENT, 0x01);
const TPM_AZURE_AIK_HANDLE: ReservedHandle = ReservedHandle::new(TPM20_HT_PERSISTENT, 0x03);
const TPM_GUEST_SECRET_HANDLE: ReservedHandle = ReservedHandle::new(TPM20_HT_PERSISTENT, 0x04);

// Reserved handles for Microsoft (Component OEM) ranges from 0x01c101c0 to 0x01c101ff
const TPM_NV_INDEX_AIK_CERT: u32 = NV_INDEX_RANGE_BASE_TCG_ASSIGNED + 0x000101d0;
const TPM_NV_INDEX_ATTESTATION_REPORT: u32 = NV_INDEX_RANGE_BASE_PLATFORM_MANUFACTURER + 0x1;
const TPM_NV_INDEX_GUEST_ATTESTATION_INPUT: u32 = NV_INDEX_RANGE_BASE_PLATFORM_MANUFACTURER + 0x2;

/// Use the SNP and TDX-defined report data size for now.
// DEVNOTE: This value should be upper bound among all the supported TEE types.
const ATTESTATION_REPORT_DATA_SIZE: usize = 0x40;

// 24 hours (in seconds)
const AK_CERT_RENEW_PERIOD: std::time::Duration = std::time::Duration::new(24 * 60 * 60, 0);
// 2 seconds
const REPORT_TIMER_PERIOD: std::time::Duration = std::time::Duration::new(2, 0);

#[derive(Debug, Copy, Clone, Inspect)]
#[repr(C)]
struct PpiState {
    pending_ppi_operation: PpiOperation,
    in_query_ppi_operation: PpiOperation,
    set_ppi_operation_state: u32,
    last_ppi_operation: PpiOperation,
    last_ppi_state: u32,
    ppi_set_operation_arg3_integer2: u32,
    tpm_capability_hash_alg_bitmap: u32,
}

impl PpiState {
    fn new() -> Self {
        Self {
            pending_ppi_operation: PpiOperation::NO_OP,
            in_query_ppi_operation: PpiOperation::NO_OP,
            set_ppi_operation_state: 0,
            last_ppi_operation: PpiOperation::NO_OP,
            last_ppi_state: 0,
            ppi_set_operation_arg3_integer2: 0,
            tpm_capability_hash_alg_bitmap: 0,
        }
    }
}

/// TPM 2.0 Mobile Reference Architecture, Section 3.1
#[derive(Debug, Copy, Clone, Inspect)]
struct ControlArea {
    /// Used to control power state transition.
    pub request: u32,
    /// Used to indicate a status.
    pub status: u32,
    /// Used to abort command processing.
    pub cancel: u32,
    /// Used to indicate that a command is available for processing
    pub start: u32,
    /// Size of the Command Buffer.
    pub command_size: u32,
    /// Physical address of the Command Buffer.
    pub command_pa: u64,
    /// Size of the Response Buffer.
    pub response_size: u32,
    /// Physical address of the Response Buffer.
    pub response_pa: u64,
}

// TODO: switch this over to open_enum!
#[allow(dead_code)]
impl ControlArea {
    const OFFSET_OF_LOC_STATE: usize = 0x00;
    const OFFSET_OF_LOC_CTRL: usize = 0x08;
    const OFFSET_OF_LOC_STS: usize = 0x0C;
    const OFFSET_OF_CRB_INTF_ID: usize = 0x30;
    const OFFSET_OF_REQUEST: usize = 0x40;
    const OFFSET_OF_STATUS: usize = 0x44;
    const OFFSET_OF_CANCEL: usize = 0x48;
    const OFFSET_OF_START: usize = 0x4C;
    const OFFSET_OF_INTERRUPT_CONTROL: usize = 0x50;
    const OFFSET_OF_COMMAND_SIZE: usize = 0x58;
    const OFFSET_OF_COMMAND_PHYSICAL_ADDRESS_LO: usize = 0x5C;
    const OFFSET_OF_COMMAND_PHYSICAL_ADDRESS_HI: usize = 0x60;
    const OFFSET_OF_RESPONSE_SIZE: usize = 0x64;
    const OFFSET_OF_RESPONSE_PHYSICAL_ADDRESS_LO: usize = 0x68;
    const OFFSET_OF_RESPONSE_PHYSICAL_ADDRESS_HI: usize = 0x6C;

    fn new() -> Self {
        Self {
            request: 0,
            status: 0,
            cancel: 0,
            start: 0,
            command_size: 0,
            command_pa: 0,
            response_size: 0,
            response_pa: 0,
        }
    }
}

#[derive(Inspect)]
#[inspect(skip)]
struct TpmRuntime {
    ppi_store: Box<dyn NonVolatileStore>,
    nvram_store: Box<dyn NonVolatileStore>,
    mem: GuestMemory,
}

#[derive(Copy, Clone, Inspect)]
pub struct TpmKeys {
    /// Attestation key in RSA public
    ak_pub: TpmRsa2kPublic,
    /// Endorsement key in RSA public
    ek_pub: TpmRsa2kPublic,
}

#[derive(Copy, Clone, Inspect, Debug, PartialEq)]
pub struct TpmRsa2kPublic {
    modulus: [u8; RSA_2K_MODULUS_SIZE],
    exponent: [u8; RSA_2K_EXPONENT_SIZE],
}

type AkCertRequestFuture = Box<
    dyn Send + Future<Output = Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync + 'static>>>,
>;

/// Implementation of [`ms_tpm_20_ref::PlatformCallbacks::monotonic_timer`]
pub type MonotonicTimer = Box<dyn Send + FnMut() -> std::time::Duration>;

#[derive(InspectMut)]
pub struct Tpm {
    // Static config
    register_layout: TpmRegisterLayout,
    refresh_tpm_seeds: bool,
    #[inspect(skip)]
    io_region: Option<(&'static str, RangeInclusive<u16>)>, // Valid only on HypervX64
    #[inspect(skip)]
    mmio_region: Vec<(&'static str, RangeInclusive<u64>)>,

    // Runtime glue
    rt: TpmRuntime,
    #[inspect(skip)]
    ak_cert_type: TpmAkCertType,

    // Sub-emulators
    #[inspect(skip)]
    tpm_engine_helper: TpmEngineHelper,

    // Runtime book-keeping
    command_buffer: [u8; TPM_PAGE_SIZE],
    #[inspect(rename = "has_pending_nvram", with = "|x| !x.lock().is_empty()")]
    pending_nvram: Arc<Mutex<Vec<u8>>>,
    #[inspect(skip)]
    async_ak_cert_request: Option<Pin<AkCertRequestFuture>>,
    #[inspect(skip)]
    waker: Option<Waker>,
    #[inspect(debug)]
    ak_cert_renew_time: Option<std::time::SystemTime>,
    #[inspect(debug)]
    attestation_report_renew_time: Option<std::time::SystemTime>,

    // Volatile state
    control_area: ControlArea,
    current_io_command: Option<TpmIoCommand>,
    requested_locality: bool,
    ppi_state: PpiState,
    // Password authorization for writing to `TPM_NV_INDEX_AIK_CERT`
    // and `TPM_NV_INDEX_ATTESTATION_REPORT` nv indexes
    auth_value: Option<u64>,
    keys: Option<TpmKeys>,
}

#[derive(Error, Debug)]
#[error(transparent)]
pub struct TpmError(#[from] TpmErrorKind);

impl From<ms_tpm_20_ref::Error> for TpmError {
    fn from(e: ms_tpm_20_ref::Error) -> Self {
        Self(TpmErrorKind::TpmPlatform(e))
    }
}

#[derive(Error, Debug)]
pub enum TpmErrorKind {
    #[error("failed to read Ppi state")]
    ReadPpiState(#[source] NonVolatileStoreError),
    #[error("failed to persist Ppi state")]
    PersistPpiState(#[source] NonVolatileStoreError),
    #[error("failed to read Nvram state")]
    ReadNvramState(#[source] NonVolatileStoreError),
    #[error("failed to persist Nvram state")]
    PersistNvramState(#[source] NonVolatileStoreError),
    #[error("failed to deserialized Ppi state")]
    InvalidPpiState,
    #[error("TPM platform error")]
    TpmPlatform(#[from] ms_tpm_20_ref::Error),
    #[error("failed to initialize TPM engine")]
    InitializeTpmEngine(#[source] TpmHelperError),
    #[error("failed to clear TPM platform context")]
    ClearTpmPlatformContext(#[source] TpmHelperError),
    #[error("failed to refresh TPM seeds")]
    RefreshTpmSeeds(#[source] TpmHelperError),
    #[error("failed to create ak public")]
    CreateAkPublic(#[source] TpmHelperError),
    #[error("failed to create ek public")]
    CreateEkPublic(#[source] TpmHelperError),
    #[error("failed to allocate guest attestation nv indices")]
    AllocateGuestAttestationNvIndices(#[source] TpmHelperError),
    #[error("failed to read from nv index")]
    ReadFromNvIndex(#[source] TpmHelperError),
    #[error("failed to write to nv index")]
    WriteToNvIndex(#[source] TpmHelperError),
    #[error("failed to get an attestation report")]
    GetAttestationReport(#[source] Box<dyn std::error::Error + Send + Sync>),
    #[error("failed to clear platform hierarchy")]
    ClearPlatformHierarchy(#[source] TpmHelperError),
    #[error("failed to set pcr banks")]
    SetPcrBanks(#[source] TpmHelperError),
}

struct TpmPlatformCallbacks {
    pending_nvram: Arc<Mutex<Vec<u8>>>,
    monotonic_timer: MonotonicTimer,
}

impl ms_tpm_20_ref::PlatformCallbacks for TpmPlatformCallbacks {
    fn commit_nv_state(&mut self, state: &[u8]) -> ms_tpm_20_ref::DynResult<()> {
        *self.pending_nvram.lock() = state.to_vec();
        Ok(())
    }

    fn get_crypt_random(&mut self, buf: &mut [u8]) -> ms_tpm_20_ref::DynResult<usize> {
        getrandom::getrandom(buf).expect("rng failure");
        Ok(buf.len())
    }

    fn monotonic_timer(&mut self) -> std::time::Duration {
        (self.monotonic_timer)()
    }

    fn get_unique_value(&self) -> &'static [u8] {
        b"hvlite vtpm"
    }
}

impl Tpm {
    pub async fn new(
        register_layout: TpmRegisterLayout,
        mem: GuestMemory,
        ppi_store: Box<dyn NonVolatileStore>,
        nvram_store: Box<dyn NonVolatileStore>,
        monotonic_timer: MonotonicTimer,
        refresh_tpm_seeds: bool,
        is_restoring: bool,
        ak_cert_type: TpmAkCertType,
        guest_secret_key: Option<Vec<u8>>,
    ) -> Result<Self, TpmError> {
        tracing::info!("initializing TPM");

        let pending_nvram = Arc::new(Mutex::new(Vec::new()));

        let tpm_engine_helper = TpmEngineHelper {
            tpm_engine: {
                MsTpm20RefPlatform::initialize(
                    Box::new(TpmPlatformCallbacks {
                        pending_nvram: pending_nvram.clone(),
                        monotonic_timer,
                    }),
                    ms_tpm_20_ref::InitKind::ColdInit,
                )?
            },
            reply_buffer: [0u8; TPM_PAGE_SIZE],
        };

        let io_region = if register_layout == TpmRegisterLayout::IoPort {
            Some((
                "io",
                TPM_DEVICE_IO_PORT_RANGE_BEGIN..=TPM_DEVICE_IO_PORT_RANGE_END,
            ))
        } else {
            None
        };

        let mmio_region = {
            let mut regions = vec![(
                "control_area",
                TPM_DEVICE_MMIO_REGION_BASE_ADDRESS
                    ..=TPM_DEVICE_MMIO_REGION_BASE_ADDRESS + TPM_DEVICE_MMIO_REGION_SIZE - 1,
            )];

            if register_layout == TpmRegisterLayout::Mmio {
                regions.push((
                    "port",
                    TPM_DEVICE_MMIO_PORT_REGION_BASE_ADDRESS
                        ..=TPM_DEVICE_MMIO_PORT_REGION_BASE_ADDRESS
                            + TPM_DEVICE_MMIO_PORT_REGION_SIZE
                            - 1,
                ));
            }

            regions
        };

        let mut tpm = Tpm {
            register_layout,
            refresh_tpm_seeds,
            io_region,
            mmio_region,

            rt: TpmRuntime {
                mem,
                ppi_store,
                nvram_store,
            },
            ak_cert_type,
            async_ak_cert_request: None,
            waker: None,

            tpm_engine_helper,

            command_buffer: [0; TPM_PAGE_SIZE],
            pending_nvram,
            ak_cert_renew_time: None,
            attestation_report_renew_time: None,

            control_area: ControlArea::new(),
            current_io_command: None,
            requested_locality: false,
            ppi_state: PpiState::new(),
            auth_value: None,
            keys: None,
        };

        if !is_restoring {
            tpm.on_first_boot(guest_secret_key).await?;
        }

        tracing::info!("TPM initialized");
        Ok(tpm)
    }

    async fn flush_pending_nvram(&mut self) -> Result<(), NonVolatileStoreError> {
        let data = {
            let mut pending_nvram = self.pending_nvram.lock();
            if pending_nvram.is_empty() {
                return Ok(());
            }
            std::mem::take(&mut *pending_nvram)
        };

        (self.rt.nvram_store).persist(data).await?;

        Ok(())
    }

    async fn on_first_boot(&mut self, guest_secret_key: Option<Vec<u8>>) -> Result<(), TpmError> {
        // Check whether or not we need to pave-over the blank TPM with our
        // existing nvmem state.
        {
            let existing_nvmem_blob = (self.rt.nvram_store)
                .restore()
                .await
                .map_err(TpmErrorKind::ReadNvramState)?;

            if let Some(blob) = existing_nvmem_blob {
                self.tpm_engine_helper.tpm_engine.reset(Some(&blob))?;
            }
        }

        self.tpm_engine_helper
            .initialize_tpm_engine()
            .map_err(TpmErrorKind::InitializeTpmEngine)?;

        // If necessary, recreate EPS & PPS.
        // The host indicates this when VM identity changes.
        if self.refresh_tpm_seeds {
            self.tpm_engine_helper
                .refresh_tpm_seeds()
                .map_err(TpmErrorKind::RefreshTpmSeeds)?;

            tracing::info!("TPM seeds have been refreshed");
        }

        // Execute any pending PPI requests set prior to reboot
        {
            let raw_ppi_state = (self.rt.ppi_store)
                .restore()
                .await
                .map_err(TpmErrorKind::ReadPpiState)?;

            if let Some(buf) = raw_ppi_state {
                let ppi_state = persist_restore::deserialize_ppi_state(buf)
                    .ok_or(TpmErrorKind::InvalidPpiState)?;

                self.ppi_state = ppi_state;
                if self.ppi_state.pending_ppi_operation != PpiOperation::NO_OP {
                    self.execute_pending_ppi()?;

                    (self.rt.ppi_store)
                        .persist(persist_restore::serialize_ppi_state(self.ppi_state))
                        .await
                        .map_err(TpmErrorKind::PersistPpiState)?;
                }
            }
        }

        if matches!(
            self.ak_cert_type,
            TpmAkCertType::Trusted(_) | TpmAkCertType::HwAttested(_)
        ) {
            // Create auth value for NV index password authorization.
            // The value needs to be preserved across live servicing.
            let mut auth_value = 0;
            getrandom::getrandom(auth_value.as_mut_bytes()).expect("rng failure");
            self.auth_value = Some(auth_value);

            // Initialize `TpmKeys`.
            // The procedure also generates randomized AK based on the TPM seed
            // and writes the AK into `TPM_AZURE_AIK_HANDLE` NV store.
            let ak_pub = self
                .tpm_engine_helper
                .create_ak_pub(self.refresh_tpm_seeds)
                .map_err(TpmErrorKind::CreateAkPublic)?;
            let ek_pub = self
                .tpm_engine_helper
                .create_ek_pub()
                .map_err(TpmErrorKind::CreateEkPublic)?;
            self.keys = Some(TpmKeys { ak_pub, ek_pub });

            // Conditionally define nv indexes for ak cert and attestation report.
            // The Nvram size can only be defined with platform hierarchy. Otherwise
            // `TPM_RC_HIERARCHY` (0c0290285) error code would return.
            // It means the Nvram index space needs to be allocated before clearing the
            // tpm hierarchy control. NV index value can be rewritten later.
            self.tpm_engine_helper
                .allocate_guest_attestation_nv_indices(
                    auth_value,
                    self.refresh_tpm_seeds,
                    matches!(self.ak_cert_type, TpmAkCertType::HwAttested(_)),
                )
                .map_err(TpmErrorKind::AllocateGuestAttestationNvIndices)?;

            // Initialize `TPM_NV_INDEX_AIK_CERT` and `TPM_NV_INDEX_ATTESTATION_REPORT`
            self.renew_ak_cert()?;
        }

        // If guest secret key is passed in, import the key into TPM.
        if let Some(guest_secret_key) = guest_secret_key {
            tracing::info!("Initializing guest secret key");

            if let Err(e) = self
                .tpm_engine_helper
                .initialize_guest_secret_key(&guest_secret_key)
            {
                // Failures are non-fatal as the feature is not necessary for booting.
                tracing::error!(
                    error = &e as &dyn std::error::Error,
                    "Failed to initialize guest secret key"
                );
            }
        }

        // clear tpm hierarchy control
        self.tpm_engine_helper
            .hierarchy_control(TPM20_RH_PLATFORM, TPM20_RH_PLATFORM, false)
            .map_err(|error| TpmHelperError::TpmCommandError {
                command_debug_info: CommandDebugInfo {
                    command_code: CommandCodeEnum::HierarchyControl,
                    auth_handle: Some(TPM20_RH_PLATFORM),
                    nv_index: None,
                },
                error,
            })
            .map_err(TpmErrorKind::ClearPlatformHierarchy)?;

        self.flush_pending_nvram()
            .await
            .map_err(TpmErrorKind::PersistNvramState)?;

        Ok(())
    }

    fn hyperv_port_read(&mut self, data: &mut [u8]) -> IoResult {
        let val = {
            let io_command = match self.current_io_command {
                Some(cmd) => cmd,
                None => {
                    tracelimit::warn_ratelimited!("Invalid tpm IO data port read (no command set)");
                    return IoResult::Ok;
                }
            };

            match io_command {
                TpmIoCommand::ESTABLISHED => self.control_area.command_pa as u32,
                TpmIoCommand::PPI_GET_PENDING_OPERATION => self.ppi_state.pending_ppi_operation.0,
                TpmIoCommand::PPI_GET_LAST_OPERATION => self.ppi_state.last_ppi_operation.0,
                TpmIoCommand::PPI_GET_LAST_RESULT => self.ppi_state.last_ppi_state,
                TpmIoCommand::PPI_SET_OPERATION => self.ppi_state.set_ppi_operation_state,
                TpmIoCommand::PPI_GET_USER_CONFIRMATION => 4,
                TpmIoCommand::GET_TCG_PROTOCOL_VERSION => {
                    io_port_interface::TcgProtocol::Tcg2 as u32
                }
                _ => {
                    tracelimit::warn_ratelimited!(?io_command, "Invalid tpm IO data read");
                    return IoResult::Ok;
                }
            }
        };

        tracing::trace!(
            ?val,
            ?self.current_io_command,
            "TPM IO read",
        );

        let data = if let Some(data) = data.get_mut(..4) {
            data
        } else {
            return IoResult::Err(IoError::InvalidAccessSize);
        };
        data.copy_from_slice(&val.to_le_bytes()[..4]);
        IoResult::Ok
    }

    fn hyperv_port_write(&mut self, control_port: bool, data: &[u8]) -> IoResult {
        let val = if let Ok(data) = data.try_into() {
            u32::from_le_bytes(data)
        } else {
            return IoResult::Err(IoError::InvalidAccessSize);
        };

        if control_port {
            self.current_io_command = Some(TpmIoCommand(val));
        } else {
            let current_io_command = match self.current_io_command {
                Some(cmd) => cmd,
                None => {
                    tracelimit::warn_ratelimited!(
                        "Invalid tpm IO data port write (no command set)"
                    );
                    return IoResult::Ok;
                }
            };

            let mut update_ppi = true;
            match current_io_command {
                TpmIoCommand::MAP_SHARED_MEMORY => {
                    self.control_area.command_size = TPM_PAGE_SIZE as u32;
                    self.control_area.command_pa = val as u64;
                    self.control_area.response_size = TPM_PAGE_SIZE as u32;
                    self.control_area.response_pa = val as u64 + (TPM_PAGE_SIZE as u64);
                    update_ppi = false;
                }
                TpmIoCommand::PPI_SET_OPERATION_ARG3_INTEGER2 => {
                    self.ppi_state.ppi_set_operation_arg3_integer2 = val;
                }
                TpmIoCommand::PPI_SET_OPERATION => {
                    self.ppi_state.pending_ppi_operation = PpiOperation(val);
                    self.ppi_state.set_ppi_operation_state = 0;
                }
                TpmIoCommand::PPI_GET_USER_CONFIRMATION => {
                    self.ppi_state.in_query_ppi_operation = PpiOperation(val);
                }
                TpmIoCommand::CAPABILITY_HASH_ALG_BITMAP => {
                    self.ppi_state.tpm_capability_hash_alg_bitmap = val;
                }
                other => {
                    tracelimit::warn_ratelimited!(?other, "unimplemented TpmIoCommand");
                    update_ppi = false;
                }
            };

            if update_ppi {
                let res = pal_async::local::block_with_io(|_| {
                    (self.rt.ppi_store)
                        .persist(persist_restore::serialize_ppi_state(self.ppi_state))
                });
                if let Err(e) = res {
                    tracing::warn!(
                        error = &e as &dyn std::error::Error,
                        "could not persist ppi state to non-volatile store"
                    );
                }
            }
        };

        tracing::trace!(
            control_port,
            ?val,
            ?self.current_io_command,
            "TPM IO write",
        );
        IoResult::Ok
    }

    fn execute_pending_ppi(&mut self) -> Result<(), TpmError> {
        self.ppi_state.last_ppi_state = match self.ppi_state.pending_ppi_operation {
            PpiOperation::CLEAR
            | PpiOperation::CLEAR_ENABLE_ACTIVATE
            | PpiOperation::ENABLE_ACTIVATE_CLEAR
            | PpiOperation::ENABLE_ACTIVATE_CLEAR_ENABLE_ACTIVATE => self
                .tpm_engine_helper
                .clear_tpm_platform_context()
                .map_err(TpmErrorKind::ClearTpmPlatformContext)?,
            PpiOperation::SET_PCR_BANKS => self.set_tpm_pcr_banks(
                self.ppi_state.tpm_capability_hash_alg_bitmap,
                self.ppi_state.ppi_set_operation_arg3_integer2,
            )?,
            other => {
                tracelimit::warn_ratelimited!(?other, "unknown pending PPI operation");
                0
            }
        };
        self.ppi_state.last_ppi_operation = self.ppi_state.pending_ppi_operation;
        self.ppi_state.pending_ppi_operation = PpiOperation::NO_OP;
        Ok(())
    }

    fn set_tpm_pcr_banks(
        &mut self,
        supported_pcr_banks: u32,
        pcr_banks_to_allocate: u32,
    ) -> Result<u32, TpmError> {
        let response_code = match self.tpm_engine_helper.pcr_allocate(
            TPM20_RH_PLATFORM,
            supported_pcr_banks,
            pcr_banks_to_allocate,
        ) {
            Err(error) => {
                if let TpmCommandError::TpmCommandFailed { response_code } = error {
                    tracelimit::error_ratelimited!(
                        err = &error as &dyn std::error::Error,
                        "tpm PcrAllocateCmd failed"
                    );

                    // Return the error code to be written to `last_ppi_state`
                    response_code
                } else {
                    // Unexpected failure
                    return Err(TpmErrorKind::SetPcrBanks(TpmHelperError::TpmCommandError {
                        command_debug_info: CommandDebugInfo {
                            command_code: CommandCodeEnum::PCR_Allocate,
                            auth_handle: Some(TPM20_RH_PLATFORM),
                            nv_index: None,
                        },
                        error,
                    })
                    .into());
                }
            }
            Ok(response_code) => response_code,
        };

        // The 1st reboot was triggered by the guest after setActivePcrBank.
        // It is necessary to put TPM into platform authorization state.
        // During the first reboot TPM20_CC_PCR_Allocate was executed.
        //
        // Below is the 2nd reboot of TPM device so that the new active PCRs take into effect.
        if response_code == tpm20proto::ResponseCode::Success as u32 {
            self.tpm_engine_helper.tpm_engine.reset(None)?;
            self.tpm_engine_helper
                .initialize_tpm_engine()
                .map_err(TpmErrorKind::InitializeTpmEngine)?;
            tracelimit::info_ratelimited!("tpm reset after sending PcrAllocateCmd");
        }

        Ok(response_code)
    }

    /// Create a new request needed by AK cert request callout.
    ///
    /// This function can only be called when `ak_cert_type` is `Trusted` or `HwAttested`.
    fn create_ak_cert_request(&mut self) -> Result<Vec<u8>, TpmError> {
        let mut guest_attestation_input = [0u8; ATTESTATION_REPORT_DATA_SIZE];
        self.tpm_engine_helper
            .read_from_nv_index(
                TPM_NV_INDEX_GUEST_ATTESTATION_INPUT,
                &mut guest_attestation_input,
            )
            .map_err(TpmErrorKind::ReadFromNvIndex)?;

        let keys = self.keys.as_ref().expect("Tpm keys uninitialized");
        let request_ak_cert_helper = self
            .ak_cert_type
            .get_ak_cert_helper()
            .expect("`ak_cert_type` should not be `None`");
        let ak_cert_request = request_ak_cert_helper
            .create_ak_cert_request(
                &keys.ak_pub.modulus,
                &keys.ak_pub.exponent,
                &keys.ek_pub.modulus,
                &keys.ek_pub.exponent,
                &guest_attestation_input,
            )
            .map_err(TpmErrorKind::GetAttestationReport)?;

        Ok(ak_cert_request)
    }

    /// Renew the nv index `TPM_NV_INDEX_ATTESTATION_REPORT` with the input data.
    ///
    /// This function is expected to only be called when `ak_cert_type` is `HwAttested`.
    fn renew_attestation_report(&mut self, data: &[u8]) -> Result<(), TpmError> {
        let auth_value = self.auth_value.expect("auth value is uninitialized");
        self.attestation_report_renew_time = Some(std::time::SystemTime::now());
        self.tpm_engine_helper
            .write_to_nv_index(auth_value, TPM_NV_INDEX_ATTESTATION_REPORT, data)
            .map_err(TpmErrorKind::WriteToNvIndex)?;

        Ok(())
    }

    /// This routine calls (via GET) external server to issue AK cert.
    /// This function can only be called when `ak_cert_type` is `Trusted` or `HwAttested`.
    fn renew_ak_cert(&mut self) -> Result<(), TpmError> {
        // Return if the request is pending
        if self.async_ak_cert_request.is_some() {
            return Ok(());
        }

        tracing::trace!("Request AK cert renewal");

        let ak_cert_request = self.create_ak_cert_request()?;
        // Store the ak cert request that includes the attestation report if `ak_cert_type` is `HwAttested`.
        if matches!(self.ak_cert_type, TpmAkCertType::HwAttested(_)) {
            self.renew_attestation_report(&ak_cert_request)?;
        }

        let request_ak_cert_helper = self
            .ak_cert_type
            .get_ak_cert_helper()
            .expect("`ak_cert_type` should not be `None`");
        let fut = {
            let request_ak_cert_helper = request_ak_cert_helper.clone();
            async move {
                request_ak_cert_helper
                    .request_ak_cert(ak_cert_request)
                    .await
            }
        };

        self.async_ak_cert_request = Some(Box::pin(fut));

        // Ensure poll gets called again.
        if let Some(waker) = self.waker.take() {
            waker.wake();
        }

        Ok(())
    }

    /// Poll the AK cert request made by `renew_ak_cert`. This function is called by [`PollDevice::poll_device`].
    fn poll_ak_cert_request(&mut self, cx: &mut std::task::Context<'_>) {
        if let Some(async_ak_cert_request) = self.async_ak_cert_request.as_mut() {
            if let Poll::Ready(result) = async_ak_cert_request.as_mut().poll(cx) {
                // Once the received the response, update the renew time using `SystemTime::now`.
                // DEVNOTE: The system time may not reflect the real time when suspension and resumption occur.
                // See more details in `refresh_ak_cert_on_nv_read`.
                let now = std::time::SystemTime::now();

                // Set the renew time regardless whether AK cert is successfully updated or not, avoiding
                // retrying on each nv read in the case of host agent being unavailable.
                // The next renew request will be made after `AK_CERT_RENEW_PERIOD` passes and
                // `refresh_ak_cert_on_nv_read` is triggered.
                self.ak_cert_renew_time = Some(now);

                // Clear `async_ak_cert_request` to allow the next renewal request.
                self.async_ak_cert_request = None;

                // Parse the response. Empty response or errors indicate that the host agent is unavailable.
                let response = match result {
                    Ok(data) if !data.is_empty() => data,
                    Ok(_data) => {
                        tracelimit::warn_ratelimited!(
                            "The requested TPM AK cert is empty - now: {:?}",
                            now.duration_since(std::time::UNIX_EPOCH),
                        );
                        return;
                    }
                    Err(error) => {
                        tracelimit::warn_ratelimited!(
                            error,
                            "Failed to request new TPM AK cert - now: {:?}",
                            now.duration_since(std::time::UNIX_EPOCH),
                        );
                        return;
                    }
                };

                let auth_value = self.auth_value.expect("auth value is uninitialized");
                if let Err(e) = self.tpm_engine_helper.write_to_nv_index(
                    auth_value,
                    TPM_NV_INDEX_AIK_CERT,
                    &response,
                ) {
                    tracelimit::error_ratelimited!(
                        error = &e as &dyn std::error::Error,
                        "Failed write new TPM AK cert to NV index"
                    );
                    return;
                }

                tracing::info!(
                    "ak cert renewal is complete - now: {:?}, size: {}",
                    now.duration_since(std::time::UNIX_EPOCH),
                    response.len()
                );
            }
        }
        self.waker = Some(cx.waker().clone());
    }

    /// Renew device attestation data (i.e., attestation report and AK cert) on NV_Read if needed
    fn refresh_device_attestation_data_on_nv_read(&mut self) {
        let Some(nv_read) = tpm20proto::protocol::NvReadCmd::deserialize(&self.command_buffer)
        else {
            return;
        };

        // Only refresh AK cert and attestation report if this is the start of an
        // NV_Read operation. Otherwise, there could be data coherency issues between
        // OS read and Underhill refresh.
        if u16::from(nv_read.offset) != 0 {
            return;
        }

        // DEVNOTE: Underhill (VTL2) currently does not have mechanisms to update the
        // system time when resuming from suspension. This means when suspension and
        // resumption occur, the 24hr system time may be longer than the 24h of real time.
        // Will revisit the implementation and make it resilient in the future.
        let now = std::time::SystemTime::now();
        let ak_cert_renew_elapsed = if let Some(renew_time) = self.ak_cert_renew_time {
            now.duration_since(renew_time)
                .expect("system clock went backwards")
        } else {
            std::time::Duration::new(0, 0)
        };

        let attestation_report_renew_elapsed =
            if let Some(renew_time) = self.attestation_report_renew_time {
                now.duration_since(renew_time)
                    .expect("system clock went backwards")
            } else {
                std::time::Duration::new(0, 0)
            };

        // On start of read of attestation report index, refresh report when
        // attestation report is supported.
        if u32::from(nv_read.nv_index) == TPM_NV_INDEX_ATTESTATION_REPORT
            && matches!(self.ak_cert_type, TpmAkCertType::HwAttested(_))
        {
            if attestation_report_renew_elapsed > REPORT_TIMER_PERIOD
                || self.attestation_report_renew_time.is_none()
            {
                // Renew tha attestation report as part of the request creation call.
                match self.create_ak_cert_request() {
                    Ok(ak_cert_request) => {
                        if let Err(e) = self.renew_attestation_report(&ak_cert_request) {
                            tracelimit::error_ratelimited!(
                                error = &e as &dyn std::error::Error,
                                "Error while renewing the attestation report on NvRead"
                            );
                        }
                    }
                    Err(e) => {
                        tracelimit::error_ratelimited!(
                            error = &e as &dyn std::error::Error,
                            "Error while creating ak cert request for renewing the attestation report"
                        );
                    }
                }
            } else {
                tracing::warn!("Hardware attestation report generation was rate limited");
            }
        } else {
            // Renew AkCert if exceeds 24 hours since renewal, or not populated,
            // and past hardware renewal period.
            let renew_cert_needed = (self.ak_cert_renew_time.is_none()
                || ak_cert_renew_elapsed > AK_CERT_RENEW_PERIOD)
                && attestation_report_renew_elapsed > REPORT_TIMER_PERIOD;

            if renew_cert_needed {
                if let Err(e) = self.renew_ak_cert() {
                    tracelimit::error_ratelimited!(
                        error = &e as &dyn std::error::Error,
                        "Error while renewing AK cert on NvRead"
                    );
                }
            }
        }
    }
}

impl ChangeDeviceState for Tpm {
    fn start(&mut self) {}

    async fn stop(&mut self) {}

    async fn reset(&mut self) {
        self.control_area = ControlArea::new();
        self.current_io_command = None;
        self.requested_locality = false;

        self.tpm_engine_helper
            .tpm_engine
            .reset(None)
            .expect("failed to reset TPM");
        self.tpm_engine_helper
            .initialize_tpm_engine()
            .expect("failed to send TPM startup commands");
        pal_async::local::block_with_io(|_| self.flush_pending_nvram())
            .expect("failed to flush nvram on reset");
    }
}

impl ChipsetDevice for Tpm {
    fn supports_pio(&mut self) -> Option<&mut dyn PortIoIntercept> {
        self.io_region.is_some().then_some(self)
    }

    fn supports_mmio(&mut self) -> Option<&mut dyn MmioIntercept> {
        Some(self)
    }

    fn supports_poll_device(&mut self) -> Option<&mut dyn PollDevice> {
        Some(self)
    }
}

impl PollDevice for Tpm {
    fn poll_device(&mut self, cx: &mut std::task::Context<'_>) {
        self.poll_ak_cert_request(cx)
    }
}

impl PortIoIntercept for Tpm {
    fn io_read(&mut self, io_port: u16, data: &mut [u8]) -> IoResult {
        let port_offset = io_port - TPM_DEVICE_IO_PORT_RANGE_BEGIN;
        if port_offset != TPM_DEVICE_IO_PORT_DATA_OFFSET {
            return IoResult::Err(IoError::InvalidRegister);
        }

        self.hyperv_port_read(data)
    }

    fn io_write(&mut self, io_port: u16, data: &[u8]) -> IoResult {
        let port_offset = io_port - TPM_DEVICE_IO_PORT_RANGE_BEGIN;
        if port_offset != TPM_DEVICE_IO_PORT_CONTROL_OFFSET
            && port_offset != TPM_DEVICE_IO_PORT_DATA_OFFSET
        {
            return IoResult::Err(IoError::InvalidRegister);
        }

        self.hyperv_port_write(port_offset == TPM_DEVICE_IO_PORT_CONTROL_OFFSET, data)
    }

    fn get_static_regions(&mut self) -> &[(&str, RangeInclusive<u16>)] {
        if let Some(region) = &self.io_region {
            std::slice::from_ref(region)
        } else {
            &[]
        }
    }
}

impl MmioIntercept for Tpm {
    fn mmio_read(&mut self, address: u64, data: &mut [u8]) -> IoResult {
        if self.register_layout == TpmRegisterLayout::Mmio
            && address == TPM_DEVICE_MMIO_PORT_DATA
            && data.len() == 4
        {
            return self.hyperv_port_read(data);
        }

        let offset = (address - TPM_DEVICE_MMIO_REGION_BASE_ADDRESS) as usize;
        match data.len() {
            1 | 2 | 4 => {}
            8 => {
                if !matches!(
                    offset,
                    ControlArea::OFFSET_OF_CRB_INTF_ID
                        | ControlArea::OFFSET_OF_COMMAND_PHYSICAL_ADDRESS_LO
                        | ControlArea::OFFSET_OF_RESPONSE_PHYSICAL_ADDRESS_LO
                ) {
                    return IoResult::Err(IoError::InvalidAccessSize);
                }
            }
            _ => {
                return IoResult::Err(IoError::InvalidAccessSize);
            }
        }

        // Some Linux guests such as when running under TDX choose to read
        // certain fields byte by byte. Floor the offset to the nearest multiple
        // of 4.
        let floor_offset = offset & !0x3;
        let byte_offset = offset - floor_offset;

        tracing::trace!(address, offset, floor_offset, byte_offset, "tpm mmio read");

        let val: u64 = match floor_offset {
            ControlArea::OFFSET_OF_LOC_STATE => {
                if self.requested_locality {
                    0x83
                } else {
                    0x81
                }
            }
            ControlArea::OFFSET_OF_LOC_CTRL => 0x0, // write only register, reads return 0
            ControlArea::OFFSET_OF_LOC_STS => 0x1,  // locality 0 has been granted access
            ControlArea::OFFSET_OF_CRB_INTF_ID => 0x4011, // CRB version 0, locality 0 only, CRB capable only
            ControlArea::OFFSET_OF_REQUEST => self.control_area.request.into(),
            ControlArea::OFFSET_OF_STATUS => self.control_area.status.into(),
            ControlArea::OFFSET_OF_CANCEL => self.control_area.cancel.into(),
            ControlArea::OFFSET_OF_START => self.control_area.start.into(),
            ControlArea::OFFSET_OF_COMMAND_SIZE => self.control_area.command_size.into(),
            ControlArea::OFFSET_OF_COMMAND_PHYSICAL_ADDRESS_LO => self.control_area.command_pa,
            ControlArea::OFFSET_OF_COMMAND_PHYSICAL_ADDRESS_HI => {
                (self.control_area.command_pa & 0xffff_ffff_0000_0000) >> 32
            }
            ControlArea::OFFSET_OF_RESPONSE_SIZE => self.control_area.response_size.into(),
            ControlArea::OFFSET_OF_RESPONSE_PHYSICAL_ADDRESS_LO => self.control_area.response_pa,
            ControlArea::OFFSET_OF_RESPONSE_PHYSICAL_ADDRESS_HI => {
                (self.control_area.response_pa & 0xffff_ffff_0000_0000) >> 32
            }
            _ => {
                return IoResult::Err(IoError::InvalidRegister);
            }
        };

        let value_array = val.to_le_bytes();
        let byte_count = data.len();
        data[..byte_count].copy_from_slice(&value_array[byte_offset..(byte_offset + byte_count)]);

        IoResult::Ok
    }

    fn mmio_write(&mut self, address: u64, data: &[u8]) -> IoResult {
        if self.register_layout == TpmRegisterLayout::Mmio
            && (address == TPM_DEVICE_MMIO_PORT_CONTROL || address == TPM_DEVICE_MMIO_PORT_DATA)
            && data.len() == 4
        {
            return self.hyperv_port_write(address == TPM_DEVICE_MMIO_PORT_CONTROL, data);
        }

        if !matches!(data.len(), 1 | 2 | 4) {
            return IoResult::Err(IoError::InvalidAccessSize);
        };
        if address & 0x3 != 0 {
            return IoResult::Err(IoError::UnalignedAccess);
        };

        let mut val: u32 = 0;
        val.as_mut_bytes()[..data.len()].copy_from_slice(data);
        match (address - TPM_DEVICE_MMIO_REGION_BASE_ADDRESS) as usize {
            ControlArea::OFFSET_OF_LOC_STATE => {}
            ControlArea::OFFSET_OF_LOC_CTRL => self.requested_locality = val & 0x2 != 0x2,
            ControlArea::OFFSET_OF_LOC_STS => {}
            ControlArea::OFFSET_OF_CRB_INTF_ID => {}
            ControlArea::OFFSET_OF_REQUEST => {}
            ControlArea::OFFSET_OF_CANCEL => {
                self.control_area.cancel = if val == 0 { 0 } else { 1 };
                self.tpm_engine_helper
                    .tpm_engine
                    .set_cancel_flag(self.control_area.cancel == 1);
            }
            ControlArea::OFFSET_OF_START => {
                if val == 1 {
                    self.control_area.start = 1;

                    let res = self
                        .rt
                        .mem
                        .read_at(self.control_area.command_pa, &mut self.command_buffer);

                    if let Err(e) = res {
                        tracelimit::error_ratelimited!(
                            error = &e as &dyn std::error::Error,
                            "Failed to read TPM command from guest memory"
                        );
                        return IoResult::Ok;
                    }

                    let cmd_header = tpm20proto::protocol::common::CmdHeader::ref_from_prefix(
                        &self.command_buffer,
                    )
                    .ok() // TODO: zerocopy: err (https://github.com/microsoft/openvmm/issues/759)
                    .and_then(|(cmd_header, _)| cmd_header.command_code.into_enum());

                    tracing::debug!(
                        cmd = ?cmd_header,
                        "executing guest tpm cmd",
                    );

                    if matches!(
                        self.ak_cert_type,
                        TpmAkCertType::Trusted(_) | TpmAkCertType::HwAttested(_)
                    ) {
                        if let Some(CommandCodeEnum::NV_Read) = cmd_header {
                            self.refresh_device_attestation_data_on_nv_read()
                        }
                    }

                    if let Err(e) = self.tpm_engine_helper.tpm_engine.execute_command(
                        &mut self.command_buffer,
                        &mut self.tpm_engine_helper.reply_buffer,
                    ) {
                        tracelimit::error_ratelimited!(
                            error = &e as &dyn std::error::Error,
                            "Error while executing TPM command"
                        );
                        return IoResult::Ok;
                    }

                    tracing::debug!(
                        response_code = ?tpm20proto::protocol::common::ReplyHeader::ref_from_prefix(
                        &self.tpm_engine_helper.reply_buffer,
                        )
                        .map(|(reply, _)| reply.response_code), // TODO: zerocopy: manual: review carefully! (https://github.com/microsoft/openvmm/issues/759)
                        "response code from guest tpm cmd",
                    );

                    let res = self.rt.mem.write_at(
                        self.control_area.response_pa,
                        &self.tpm_engine_helper.reply_buffer,
                    );

                    if let Err(e) = res {
                        tracelimit::error_ratelimited!(
                            error = &e as &dyn std::error::Error,
                            "Failed to write TPM reply into guest memory"
                        );
                        return IoResult::Ok;
                    }

                    self.control_area.start = 0;
                }
            }
            _ => return IoResult::Err(IoError::InvalidRegister),
        }

        let res = pal_async::local::block_with_io(|_| self.flush_pending_nvram());
        if let Err(e) = res {
            tracing::warn!(
                error = &e as &dyn std::error::Error,
                "could not commit nvram to non-volatile store"
            );
        };

        IoResult::Ok
    }

    fn get_static_regions(&mut self) -> &[(&str, RangeInclusive<u64>)] {
        &self.mmio_region
    }
}

/// The IO port interface bespoke to the Hyper-V implementation of the vTPM.
mod io_port_interface {
    use inspect::Inspect;
    use zerocopy::FromBytes;

    use zerocopy::Immutable;
    use zerocopy::IntoBytes;
    use zerocopy::KnownLayout;

    open_enum::open_enum! {
        /// I/O port command definitions
        #[derive(Inspect, IntoBytes, Immutable, KnownLayout, FromBytes)]
        #[inspect(debug)]
        pub enum TpmIoCommand: u32 {
            /// It can be used for engine vs. guest version negotiation. Not used.
            VERSION = 0,
            /// Map command-response interface buffer.
            MAP_SHARED_MEMORY = 1,
            /// Query host if map is succeeded.
            ESTABLISHED = 2,
            /// Get pending TPM operation requested by the OS.
            PPI_GET_PENDING_OPERATION = 3,
            /// Get TPM Operation Response to OS.
            PPI_GET_LAST_OPERATION = 5,
            PPI_GET_LAST_RESULT = 6,
            /// Set TPM operation requested by the OS.
            /// TpmIoPPISetOperationArg3Integer1
            PPI_SET_OPERATION = 7,
            /// Get user confirmation status for operation. Used in PPI over ACPI.
            PPI_GET_USER_CONFIRMATION = 8,
            /// The command to set PPI func ID 7 Arg3 (Package) Integer 2.
            PPI_SET_OPERATION_ARG3_INTEGER2 = 32,
            /// Get Tcg Protocol Version.
            GET_TCG_PROTOCOL_VERSION = 64,
            /// Report the supported hash bitmap in TPM capability.
            CAPABILITY_HASH_ALG_BITMAP = 65,
        }
    }

    #[allow(dead_code)]
    #[repr(u32)]
    #[derive(Debug, Copy, Clone)]
    pub enum TcgProtocol {
        TrEe = 0,
        Tcg2 = 1,
    }

    open_enum::open_enum! {
        /// Table 2: Physical Presence Interface Operation Summary for TPM 2.0
        ///
        /// Part of the Physical Presence Interface Specification - TCG PC Client Platform
        #[derive(Inspect, IntoBytes, Immutable, KnownLayout, FromBytes)]
        #[inspect(debug)]
        pub enum PpiOperation: u32 {
            NO_OP = 0,
            ENABLE = 1,
            DISABLE = 2,
            ACTIVATE = 3,
            DEACTIVATE = 4,
            CLEAR = 5,
            ENABLE_ACTIVATE = 6,
            DEACTIVATE_DISABLE = 7,
            SET_OWNER_INSTALL_TRUE = 8,
            SET_OWNER_INSTALL_FALSE = 9,
            ENABLE_ACTIVATE_SET_OWNER_INSTALL_TRUE = 10,
            SET_OWNER_INSTALL_FALSE_DEACTIVATE_DISABLE = 11,
            CLEAR_ENABLE_ACTIVATE = 14,
            SET_NO_PPI_PROVISION_FALSE = 15,
            SET_NO_PPI_PROVISION_TRUE = 16,
            ENABLE_ACTIVATE_CLEAR = 21,
            ENABLE_ACTIVATE_CLEAR_ENABLE_ACTIVATE = 22,
            SET_PCR_BANKS = 23,
        }
    }
}

mod persist_restore {
    use super::*;

    mod state {
        use zerocopy::FromBytes;

        use zerocopy::Immutable;
        use zerocopy::IntoBytes;
        use zerocopy::KnownLayout;

        #[derive(Debug, Copy, Clone, IntoBytes, Immutable, KnownLayout, FromBytes)]
        #[repr(C)]
        pub struct PersistedPpiState {
            pub pending_ppi_operation: u32,
            pub in_query_ppi_operation: u32,
            pub set_ppi_operation_state: u32,
            pub last_ppi_operation: u32,
            pub last_ppi_state: u32,
            pub ppi_set_operation_arg3_integer2: u32,
            pub tpm_capability_hash_alg_bitmap: u32,
        }
    }

    pub(crate) fn deserialize_ppi_state(buf: Vec<u8>) -> Option<PpiState> {
        let saved = state::PersistedPpiState::read_from_bytes(buf.as_bytes()).ok()?; // TODO: zerocopy: map_err (https://github.com/microsoft/openvmm/issues/759)
        let state::PersistedPpiState {
            pending_ppi_operation,
            in_query_ppi_operation,
            set_ppi_operation_state,
            last_ppi_operation,
            last_ppi_state,
            ppi_set_operation_arg3_integer2,
            tpm_capability_hash_alg_bitmap,
        } = saved;

        Some(PpiState {
            pending_ppi_operation: PpiOperation(pending_ppi_operation),
            in_query_ppi_operation: PpiOperation(in_query_ppi_operation),
            set_ppi_operation_state,
            last_ppi_operation: PpiOperation(last_ppi_operation),
            last_ppi_state,
            ppi_set_operation_arg3_integer2,
            tpm_capability_hash_alg_bitmap,
        })
    }

    pub(crate) fn serialize_ppi_state(state: PpiState) -> Vec<u8> {
        let PpiState {
            pending_ppi_operation,
            in_query_ppi_operation,
            set_ppi_operation_state,
            last_ppi_operation,
            last_ppi_state,
            ppi_set_operation_arg3_integer2,
            tpm_capability_hash_alg_bitmap,
        } = state;

        state::PersistedPpiState {
            pending_ppi_operation: pending_ppi_operation.0,
            in_query_ppi_operation: in_query_ppi_operation.0,
            set_ppi_operation_state,
            last_ppi_operation: last_ppi_operation.0,
            last_ppi_state,
            ppi_set_operation_arg3_integer2,
            tpm_capability_hash_alg_bitmap,
        }
        .as_bytes()
        .to_vec()
    }
}

mod save_restore {
    use super::*;
    use vmcore::save_restore::RestoreError;
    use vmcore::save_restore::SaveError;
    use vmcore::save_restore::SaveRestore;

    mod state {
        use mesh::payload::Protobuf;
        use vmcore::save_restore::SavedStateRoot;

        const RSA_2K_MODULUS_SIZE: usize = 256;
        const RSA_2K_EXPONENT_SIZE: usize = 3;

        #[derive(Protobuf)]
        #[mesh(package = "tpm")]
        pub struct SavedControlArea {
            #[mesh(1)]
            pub request: u32,
            #[mesh(2)]
            pub status: u32,
            #[mesh(3)]
            pub cancel: u32,
            #[mesh(4)]
            pub start: u32,
            #[mesh(5)]
            pub command_size: u32,
            #[mesh(6)]
            pub command_pa: u64,
            #[mesh(7)]
            pub response_size: u32,
            #[mesh(8)]
            pub response_pa: u64,
        }

        #[derive(Protobuf)]
        #[mesh(package = "tpm")]
        pub struct SavedPpiState {
            #[mesh(1)]
            pub pending_ppi_operation: u32,
            #[mesh(2)]
            pub in_query_ppi_operation: u32,
            #[mesh(3)]
            pub set_ppi_operation_state: u32,
            #[mesh(4)]
            pub last_ppi_operation: u32,
            #[mesh(5)]
            pub last_ppi_state: u32,
            #[mesh(6)]
            pub ppi_set_operation_arg3_integer2: u32,
            #[mesh(7)]
            pub tpm_capability_hash_alg_bitmap: u32,
        }

        #[derive(Protobuf)]
        #[mesh(package = "tpm")]
        pub struct SavedTpmKeys {
            #[mesh(1)]
            pub ak_pub_modulus: [u8; RSA_2K_MODULUS_SIZE],
            #[mesh(2)]
            pub ak_pub_exponent: [u8; RSA_2K_EXPONENT_SIZE],
            #[mesh(3)]
            pub ek_pub_modulus: [u8; RSA_2K_MODULUS_SIZE],
            #[mesh(4)]
            pub ek_pub_exponent: [u8; RSA_2K_EXPONENT_SIZE],
        }

        #[derive(Protobuf, SavedStateRoot)]
        #[mesh(package = "tpm")]
        pub struct SavedState {
            #[mesh(1)]
            pub control_area: SavedControlArea,
            #[mesh(2)]
            pub current_io_command: Option<u32>,
            #[mesh(3)]
            pub requested_locality: bool,
            #[mesh(4)]
            pub ppi_state: SavedPpiState,
            #[mesh(5)]
            pub tpm_state_blob: Vec<u8>,
            // Experimental fields to avoid breaking changes
            // TODO CVM: Remove the explicit numbering once live servicing design is finialized
            #[mesh(60)]
            pub auth_value: Option<u64>,
            #[mesh(61)]
            pub keys: Option<SavedTpmKeys>,
        }
    }

    #[derive(Error, Debug)]
    pub enum TpmRestoreError {
        #[error("failed to restore tpm library runtime state")]
        TpmRuntimeLib(#[source] ms_tpm_20_ref::Error),
    }

    #[derive(Error, Debug)]
    pub enum TpmSaveError {
        #[error("save is blocked when there is an outstanding AK Cert request")]
        OutstandingAkCertRequest,
    }

    impl SaveRestore for Tpm {
        type SavedState = state::SavedState;

        fn save(&mut self) -> Result<Self::SavedState, SaveError> {
            // Block save requests when there is an outstanding ak cert request.
            //
            // DEVNOTE:
            // - The device itself does not save/restore the async request, and
            // we need to think more about what it means to save the outstanding request
            // and what the API should be.
            // - The existing implementation with the GET has a host issue where leaving
            // this request in-flight during a servicing operation can lead to bad host
            // behavior on older hosts.
            if self.async_ak_cert_request.is_some() {
                return Err(SaveError::Other(
                    TpmSaveError::OutstandingAkCertRequest.into(),
                ));
            }

            let control_area = {
                let ControlArea {
                    request,
                    status,
                    cancel,
                    start,
                    command_size,
                    command_pa,
                    response_size,
                    response_pa,
                } = self.control_area;

                state::SavedControlArea {
                    request,
                    status,
                    cancel,
                    start,
                    command_size,
                    command_pa,
                    response_size,
                    response_pa,
                }
            };

            let ppi_state = {
                let PpiState {
                    pending_ppi_operation,
                    in_query_ppi_operation,
                    set_ppi_operation_state,
                    last_ppi_operation,
                    last_ppi_state,
                    ppi_set_operation_arg3_integer2,
                    tpm_capability_hash_alg_bitmap,
                } = self.ppi_state;

                state::SavedPpiState {
                    pending_ppi_operation: pending_ppi_operation.0,
                    in_query_ppi_operation: in_query_ppi_operation.0,
                    set_ppi_operation_state,
                    last_ppi_operation: last_ppi_operation.0,
                    last_ppi_state,
                    ppi_set_operation_arg3_integer2,
                    tpm_capability_hash_alg_bitmap,
                }
            };

            // TODO CVM: The design of live servicing for CVM is not finalized.
            //           This behavior is subject to change.
            let keys = self.keys.as_ref().map(|keys| state::SavedTpmKeys {
                ak_pub_modulus: keys.ak_pub.modulus,
                ak_pub_exponent: keys.ak_pub.exponent,
                ek_pub_modulus: keys.ek_pub.modulus,
                ek_pub_exponent: keys.ek_pub.exponent,
            });

            let saved_state = state::SavedState {
                control_area,
                current_io_command: self.current_io_command.map(|x| x.0),
                requested_locality: self.requested_locality,
                ppi_state,
                tpm_state_blob: self.tpm_engine_helper.tpm_engine.save_state(),
                auth_value: self.auth_value,
                keys,
            };

            Ok(saved_state)
        }

        fn restore(&mut self, state: Self::SavedState) -> Result<(), RestoreError> {
            let state::SavedState {
                control_area,
                current_io_command,
                requested_locality,
                ppi_state,
                tpm_state_blob,
                auth_value,
                keys,
            } = state;

            self.control_area = {
                let state::SavedControlArea {
                    request,
                    status,
                    cancel,
                    start,
                    command_size,
                    command_pa,
                    response_size,
                    response_pa,
                } = control_area;

                ControlArea {
                    request,
                    status,
                    cancel,
                    start,
                    command_size,
                    command_pa,
                    response_size,
                    response_pa,
                }
            };
            self.current_io_command = current_io_command.map(TpmIoCommand);
            self.ppi_state = {
                let state::SavedPpiState {
                    pending_ppi_operation,
                    in_query_ppi_operation,
                    set_ppi_operation_state,
                    last_ppi_operation,
                    last_ppi_state,
                    ppi_set_operation_arg3_integer2,
                    tpm_capability_hash_alg_bitmap,
                } = ppi_state;

                PpiState {
                    pending_ppi_operation: PpiOperation(pending_ppi_operation),
                    in_query_ppi_operation: PpiOperation(in_query_ppi_operation),
                    set_ppi_operation_state,
                    last_ppi_operation: PpiOperation(last_ppi_operation),
                    last_ppi_state,
                    ppi_set_operation_arg3_integer2,
                    tpm_capability_hash_alg_bitmap,
                }
            };
            self.requested_locality = requested_locality;
            self.tpm_engine_helper
                .tpm_engine
                .restore_state(tpm_state_blob)
                .map_err(TpmRestoreError::TpmRuntimeLib)
                .map_err(|e| RestoreError::Other(e.into()))?;

            self.auth_value = auth_value;
            self.keys = keys.map(|keys| TpmKeys {
                ak_pub: TpmRsa2kPublic {
                    modulus: keys.ak_pub_modulus,
                    exponent: keys.ak_pub_exponent,
                },
                ek_pub: TpmRsa2kPublic {
                    modulus: keys.ek_pub_modulus,
                    exponent: keys.ek_pub_exponent,
                },
            });

            Ok(())
        }
    }
}
