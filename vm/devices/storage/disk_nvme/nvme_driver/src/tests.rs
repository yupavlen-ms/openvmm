// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use crate::NvmeDriver;
use chipset_device::mmio::ExternallyManagedMmioIntercepts;
use chipset_device::mmio::MmioIntercept;
use chipset_device::pci::PciConfigSpace;
use guid::Guid;
use inspect::Inspect;
use inspect::InspectMut;
use nvme::NvmeControllerCaps;
use nvme_spec::Cap;
use nvme_spec::nvm::DsmRange;
use pal_async::DefaultDriver;
use pal_async::async_test;
use parking_lot::Mutex;
use pci_core::msi::MsiInterruptSet;
use scsi_buffers::OwnedRequestBuffers;
use std::sync::Arc;
use test_with_tracing::test;
use user_driver::DeviceBacking;
use user_driver::DeviceRegisterIo;
use user_driver::DmaClient;
use user_driver::interrupt::DeviceInterrupt;
use user_driver_emulated_mock::DeviceTestMemory;
use user_driver_emulated_mock::EmulatedDevice;
use user_driver_emulated_mock::Mapping;
use vmcore::vm_task::SingleDriverBackend;
use vmcore::vm_task::VmTaskDriverSource;
use zerocopy::IntoBytes;

#[async_test]
async fn test_nvme_driver_direct_dma(driver: DefaultDriver) {
    test_nvme_driver(driver, true).await;
}

#[async_test]
async fn test_nvme_driver_bounce_buffer(driver: DefaultDriver) {
    test_nvme_driver(driver, false).await;
}

#[async_test]
async fn test_nvme_save_restore(driver: DefaultDriver) {
    test_nvme_save_restore_inner(driver).await;
}

#[async_test]
async fn test_nvme_ioqueue_max_mqes(driver: DefaultDriver) {
    const MSIX_COUNT: u16 = 2;
    const IO_QUEUE_COUNT: u16 = 64;
    const CPU_COUNT: u32 = 64;

    // Memory setup
    let pages = 1000;
    let device_test_memory = DeviceTestMemory::new(pages, false, "test_nvme_ioqueue_max_mqes");
    let guest_mem = device_test_memory.guest_memory();
    let dma_client = device_test_memory.dma_client();

    // Controller Driver Setup
    let driver_source = VmTaskDriverSource::new(SingleDriverBackend::new(driver));
    let mut msi_set = MsiInterruptSet::new();
    let nvme = nvme::NvmeController::new(
        &driver_source,
        guest_mem,
        &mut msi_set,
        &mut ExternallyManagedMmioIntercepts,
        NvmeControllerCaps {
            msix_count: MSIX_COUNT,
            max_io_queues: IO_QUEUE_COUNT,
            subsystem_id: Guid::new_random(),
        },
    );

    let mut device = NvmeTestEmulatedDevice::new(nvme, msi_set, dma_client.clone());

    // Mock response at offset 0 since that is where Cap will be accessed
    let max_u16: u16 = 65535;
    let cap: Cap = Cap::new().with_mqes_z(max_u16);
    device.set_mock_response_u64(Some((0, cap.into())));

    let driver = NvmeDriver::new(&driver_source, CPU_COUNT, device, false).await;
    assert!(driver.is_ok());
}

#[async_test]
async fn test_nvme_ioqueue_invalid_mqes(driver: DefaultDriver) {
    const MSIX_COUNT: u16 = 2;
    const IO_QUEUE_COUNT: u16 = 64;
    const CPU_COUNT: u32 = 64;

    // Memory setup
    let pages = 1000;
    let device_test_memory = DeviceTestMemory::new(pages, false, "test_nvme_ioqueue_invalid_mqes");
    let guest_mem = device_test_memory.guest_memory();
    let dma_client = device_test_memory.dma_client();

    let driver_source = VmTaskDriverSource::new(SingleDriverBackend::new(driver));
    let mut msi_set = MsiInterruptSet::new();
    let nvme = nvme::NvmeController::new(
        &driver_source,
        guest_mem,
        &mut msi_set,
        &mut ExternallyManagedMmioIntercepts,
        NvmeControllerCaps {
            msix_count: MSIX_COUNT,
            max_io_queues: IO_QUEUE_COUNT,
            subsystem_id: Guid::new_random(),
        },
    );

    let mut device = NvmeTestEmulatedDevice::new(nvme, msi_set, dma_client.clone());

    // Setup mock response at offset 0
    let cap: Cap = Cap::new().with_mqes_z(0);
    device.set_mock_response_u64(Some((0, cap.into())));
    let driver = NvmeDriver::new(&driver_source, CPU_COUNT, device, false).await;

    assert!(driver.is_err());
}

async fn test_nvme_driver(driver: DefaultDriver, allow_dma: bool) {
    const MSIX_COUNT: u16 = 2;
    const IO_QUEUE_COUNT: u16 = 64;
    const CPU_COUNT: u32 = 64;

    // Arrange: Create 8MB of space. First 4MB for the device and second 4MB for the payload.
    let pages = 1024; // 4MB
    let device_test_memory = DeviceTestMemory::new(pages * 2, allow_dma, "test_nvme_driver");
    let guest_mem = device_test_memory.guest_memory(); // Access to 0-8MB
    let dma_client = device_test_memory.dma_client(); // Access 0-4MB
    let payload_mem = device_test_memory.payload_mem(); // Access 4-8MB. This will allow dma if the `allow_dma` flag is set.

    // Arrange: Create the NVMe controller and driver.
    let driver_source = VmTaskDriverSource::new(SingleDriverBackend::new(driver));
    let mut msi_set = MsiInterruptSet::new();
    let nvme = nvme::NvmeController::new(
        &driver_source,
        guest_mem.clone(),
        &mut msi_set,
        &mut ExternallyManagedMmioIntercepts,
        NvmeControllerCaps {
            msix_count: MSIX_COUNT,
            max_io_queues: IO_QUEUE_COUNT,
            subsystem_id: Guid::new_random(),
        },
    );

    nvme.client() // 2MB namespace
        .add_namespace(1, disklayer_ram::ram_disk(2 << 20, false).unwrap())
        .await
        .unwrap();
    let device = NvmeTestEmulatedDevice::new(nvme, msi_set, dma_client.clone());
    let driver = NvmeDriver::new(&driver_source, CPU_COUNT, device, false)
        .await
        .unwrap();
    let namespace = driver.namespace(1).await.unwrap();

    // Act: Write 1024 bytes of data to disk starting at LBA 1.
    let buf_range = OwnedRequestBuffers::linear(0, 16384, true); // 32 blocks
    payload_mem.write_at(0, &[0xcc; 4096]).unwrap();
    namespace
        .write(
            0,
            1,
            2,
            false,
            &payload_mem,
            buf_range.buffer(&payload_mem).range(),
        )
        .await
        .unwrap();

    // Act: Read 16384 bytes of data from disk starting at LBA 0.
    namespace
        .read(
            1,
            0,
            32,
            &payload_mem,
            buf_range.buffer(&payload_mem).range(),
        )
        .await
        .unwrap();
    let mut v = [0; 4096];
    payload_mem.read_at(0, &mut v).unwrap();

    // Assert: First block should be 0x00 since we never wrote to it. Followed by 1024 bytes of 0xcc.
    assert_eq!(&v[..512], &[0; 512]);
    assert_eq!(&v[512..1536], &[0xcc; 1024]);
    assert!(v[1536..].iter().all(|&x| x == 0));

    namespace
        .deallocate(
            0,
            &[
                DsmRange {
                    context_attributes: 0,
                    starting_lba: 1000,
                    lba_count: 2000,
                },
                DsmRange {
                    context_attributes: 0,
                    starting_lba: 2,
                    lba_count: 2,
                },
            ],
        )
        .await
        .unwrap();

    assert_eq!(driver.fallback_cpu_count(), 0);

    // Test the fallback queue functionality.
    namespace
        .read(
            63,
            0,
            32,
            &payload_mem,
            buf_range.buffer(&guest_mem).range(),
        )
        .await
        .unwrap();

    assert_eq!(driver.fallback_cpu_count(), 1);

    let mut v = [0; 4096];
    payload_mem.read_at(0, &mut v).unwrap();
    assert_eq!(&v[..512], &[0; 512]);
    assert_eq!(&v[512..1024], &[0xcc; 512]);
    assert!(v[1024..].iter().all(|&x| x == 0));

    driver.shutdown().await;
}

async fn test_nvme_save_restore_inner(driver: DefaultDriver) {
    const MSIX_COUNT: u16 = 2;
    const IO_QUEUE_COUNT: u16 = 64;
    const CPU_COUNT: u32 = 64;

    // Memory setup
    let pages = 1000;
    let device_test_memory = DeviceTestMemory::new(pages, false, "test_nvme_save_restore_inner");
    let guest_mem = device_test_memory.guest_memory();
    let dma_client = device_test_memory.dma_client();

    let driver_source = VmTaskDriverSource::new(SingleDriverBackend::new(driver.clone()));
    let mut msi_x = MsiInterruptSet::new();
    let nvme_ctrl = nvme::NvmeController::new(
        &driver_source,
        guest_mem.clone(),
        &mut msi_x,
        &mut ExternallyManagedMmioIntercepts,
        NvmeControllerCaps {
            msix_count: MSIX_COUNT,
            max_io_queues: IO_QUEUE_COUNT,
            subsystem_id: Guid::new_random(),
        },
    );

    // Add a namespace so Identify Namespace command will succeed later.
    nvme_ctrl
        .client()
        .add_namespace(1, disklayer_ram::ram_disk(2 << 20, false).unwrap())
        .await
        .unwrap();

    let device = NvmeTestEmulatedDevice::new(nvme_ctrl, msi_x, dma_client.clone());
    let mut nvme_driver = NvmeDriver::new(&driver_source, CPU_COUNT, device, false)
        .await
        .unwrap();
    let _ns1 = nvme_driver.namespace(1).await.unwrap();
    let saved_state = nvme_driver.save().await.unwrap();
    // As of today we do not save namespace data to avoid possible conflict
    // when namespace has changed during servicing.
    // TODO: Review and re-enable in future.
    assert_eq!(saved_state.namespaces.len(), 0);

    // Create a second set of devices since the ownership has been moved.
    let mut new_msi_x = MsiInterruptSet::new();
    let mut new_nvme_ctrl = nvme::NvmeController::new(
        &driver_source,
        guest_mem.clone(),
        &mut new_msi_x,
        &mut ExternallyManagedMmioIntercepts,
        NvmeControllerCaps {
            msix_count: MSIX_COUNT,
            max_io_queues: IO_QUEUE_COUNT,
            subsystem_id: Guid::new_random(),
        },
    );

    let mut backoff = user_driver::backoff::Backoff::new(&driver);

    // Enable the controller for keep-alive test.
    let mut dword = 0u32;
    // Read Register::CC.
    new_nvme_ctrl.read_bar0(0x14, dword.as_mut_bytes()).unwrap();
    // Set CC.EN.
    dword |= 1;
    new_nvme_ctrl.write_bar0(0x14, dword.as_bytes()).unwrap();
    // Wait for CSTS.RDY to set.
    backoff.back_off().await;

    let _new_device = NvmeTestEmulatedDevice::new(new_nvme_ctrl, new_msi_x, dma_client.clone());
    // TODO: Memory restore is disabled for emulated DMA, uncomment once fixed.
    // let _new_nvme_driver = NvmeDriver::restore(&driver_source, CPU_COUNT, new_device, &saved_state)
    //     .await
    //     .unwrap();
}

#[derive(Inspect)]
pub struct NvmeTestEmulatedDevice<T: InspectMut, U: DmaClient> {
    device: EmulatedDevice<T, U>,
    #[inspect(debug)]
    mocked_response_u32: Arc<Mutex<Option<(usize, u32)>>>,
    #[inspect(debug)]
    mocked_response_u64: Arc<Mutex<Option<(usize, u64)>>>,
}

#[derive(Inspect)]
pub struct NvmeTestMapping<T> {
    mapping: Mapping<T>,
    #[inspect(debug)]
    mocked_response_u32: Arc<Mutex<Option<(usize, u32)>>>,
    #[inspect(debug)]
    mocked_response_u64: Arc<Mutex<Option<(usize, u64)>>>,
}

impl<T: PciConfigSpace + MmioIntercept + InspectMut, U: DmaClient> NvmeTestEmulatedDevice<T, U> {
    /// Creates a new emulated device, wrapping `device`, using the provided MSI controller.
    pub fn new(device: T, msi_set: MsiInterruptSet, dma_client: Arc<U>) -> Self {
        Self {
            device: EmulatedDevice::new(device, msi_set, dma_client.clone()),
            mocked_response_u32: Arc::new(Mutex::new(None)),
            mocked_response_u64: Arc::new(Mutex::new(None)),
        }
    }

    // TODO: set_mock_response_u32 is intentionally not implemented to avoid dead code.
    pub fn set_mock_response_u64(&mut self, mapping: Option<(usize, u64)>) {
        let mut mock_response = self.mocked_response_u64.lock();
        *mock_response = mapping;
    }
}

/// Implementation of DeviceBacking trait for NvmeTestEmulatedDevice
impl<T: 'static + Send + InspectMut + MmioIntercept, U: 'static + DmaClient> DeviceBacking
    for NvmeTestEmulatedDevice<T, U>
{
    type Registers = NvmeTestMapping<T>;

    fn id(&self) -> &str {
        self.device.id()
    }

    fn map_bar(&mut self, n: u8) -> anyhow::Result<Self::Registers> {
        Ok(NvmeTestMapping {
            mapping: self.device.map_bar(n).unwrap(),
            mocked_response_u32: Arc::clone(&self.mocked_response_u32),
            mocked_response_u64: Arc::clone(&self.mocked_response_u64),
        })
    }

    fn dma_client(&self) -> Arc<dyn DmaClient> {
        self.device.dma_client()
    }

    fn max_interrupt_count(&self) -> u32 {
        self.device.max_interrupt_count()
    }

    fn map_interrupt(&mut self, msix: u32, _cpu: u32) -> anyhow::Result<DeviceInterrupt> {
        self.device.map_interrupt(msix, _cpu)
    }
}

impl<T: MmioIntercept + Send> DeviceRegisterIo for NvmeTestMapping<T> {
    fn len(&self) -> usize {
        self.mapping.len()
    }

    fn read_u32(&self, offset: usize) -> u32 {
        let mock_response = self.mocked_response_u32.lock();

        // Intercept reads to the mocked offset address
        if let Some((mock_offset, mock_data)) = *mock_response {
            if mock_offset == offset {
                return mock_data;
            }
        }

        self.mapping.read_u32(offset)
    }

    fn read_u64(&self, offset: usize) -> u64 {
        let mock_response = self.mocked_response_u64.lock();

        // Intercept reads to the mocked offset address
        if let Some((mock_offset, mock_data)) = *mock_response {
            if mock_offset == offset {
                return mock_data;
            }
        }

        self.mapping.read_u64(offset)
    }

    fn write_u32(&self, offset: usize, data: u32) {
        self.mapping.write_u32(offset, data);
    }

    fn write_u64(&self, offset: usize, data: u64) {
        self.mapping.write_u64(offset, data);
    }
}
