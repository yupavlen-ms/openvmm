// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! VM resource definitions for virtio devices.
//!
//! Device-specific definitions are here to avoid needing to pull in a device
//! implementation crate just to construct the device's config.

#![expect(missing_docs)]
#![forbid(unsafe_code)]

use mesh::MeshPayload;
use vm_resource::Resource;
use vm_resource::ResourceId;
use vm_resource::kind::PciDeviceHandleKind;
use vm_resource::kind::VirtioDeviceHandle;

/// A resource for mapping a virtio device as a PCI device.
#[derive(MeshPayload)]
pub struct VirtioPciDeviceHandle(pub Resource<VirtioDeviceHandle>);

impl ResourceId<PciDeviceHandleKind> for VirtioPciDeviceHandle {
    const ID: &'static str = "virtio";
}

pub mod p9 {
    use mesh::MeshPayload;
    use vm_resource::ResourceId;
    use vm_resource::kind::VirtioDeviceHandle;

    #[derive(MeshPayload)]
    pub struct VirtioPlan9Handle {
        pub tag: String,
        pub root_path: String,
        pub debug: bool,
    }

    impl ResourceId<VirtioDeviceHandle> for VirtioPlan9Handle {
        const ID: &'static str = "virtio-9p";
    }
}

pub mod fs {
    use mesh::MeshPayload;
    use vm_resource::ResourceId;
    use vm_resource::kind::VirtioDeviceHandle;

    #[derive(MeshPayload)]
    pub struct VirtioFsHandle {
        pub tag: String,
        pub fs: VirtioFsBackend,
    }

    #[derive(MeshPayload)]
    pub enum VirtioFsBackend {
        HostFs {
            root_path: String,
            mount_options: String,
        },
        SectionFs {
            root_path: String,
        },
    }

    impl ResourceId<VirtioDeviceHandle> for VirtioFsHandle {
        const ID: &'static str = "virtiofs";
    }
}

pub mod pmem {
    use mesh::MeshPayload;
    use vm_resource::ResourceId;
    use vm_resource::kind::VirtioDeviceHandle;

    #[derive(MeshPayload)]
    pub struct VirtioPmemHandle {
        pub path: String,
    }

    impl ResourceId<VirtioDeviceHandle> for VirtioPmemHandle {
        const ID: &'static str = "virtio-pmem";
    }
}

pub mod net {
    use mesh::MeshPayload;
    use net_backend_resources::mac_address::MacAddress;
    use vm_resource::Resource;
    use vm_resource::ResourceId;
    use vm_resource::kind::NetEndpointHandleKind;
    use vm_resource::kind::VirtioDeviceHandle;

    #[derive(MeshPayload)]
    pub struct VirtioNetHandle {
        pub max_queues: Option<u16>,
        pub mac_address: MacAddress,
        pub endpoint: Resource<NetEndpointHandleKind>,
    }

    impl ResourceId<VirtioDeviceHandle> for VirtioNetHandle {
        const ID: &'static str = "virtio-net";
    }
}
