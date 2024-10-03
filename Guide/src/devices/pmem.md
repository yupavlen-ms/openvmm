# Virtual Persistent Memory (VPMEM)

In the future, OpenVMM will need to support Virtual Persistent Memory devices.
Linux containers on Windows rely on file-backed VPMEM devices for container layers.
VPMEM devices can be backed by either physical PMEM hardware, or a section
(which could be file-backed) on the host. VPMEM metadata can be provided
via VirtIO-PMEM or the Hyper-V guest ACPI implementation.

## Guest interaction

To let the guest interact with a section-backed vpmem device,
the whp::Partition::map_range function will be used. A section can be created,
and then its physical address can be mapped into the guest's GPA space.
The guest then learns where the device via either VirtIO or ACPI.

### VirtIO-PMEM

The pmem extension to VirtIO will only support Linux guests. However, it is likely
simpler to get started with, and may support hot-add and hot-remove more easily.
The VirtIO communication channel is used to indicate to the guest where in GPA space
the VPMEM devices are found.
A draft spec can be found
[here](https://lists.oasis-open.org/archives/virtio-dev/201903/msg00083.html).

### Hyper-V ACPI

The Hyper-V UEFI firmware implements the ACPI NVDIMM specification. This spec
is how physical PMEM device drivers get device metadata, and also supports rich
error reporting. This approach supports both Windows and Linux guests without special
guest drivers. A reference implementation for how to interact with the guest ACPI code
can be found in the Hyper-V VPMEM Virtual device, written in C++.

## Limitations

Supporting guest-assigned physical PMEM devices on Windows will require additional
WHP platform functionality, as today there is no way to assign physical devices to
a WHP partition.
