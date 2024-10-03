# Block storage

OpenVMM implements block devices in two layers: devices and disks. A disk is the
backing implementations of a virtual block device, and a device is the interface
by which the guest accesses disks.

## Devices

### StorVSP

Currently the only supported device is StorVSP.

## Disks

Currently, all disks use the `ScsiDisk` type to implement the SCSI protocol.
This allows the disk implementations to focus on the simpler functionality that
distinguishes each disk type: the geometry of the disk, and the behavior of
reads, writes, and flushes.

### File disk

A file disk is a raw image, without any header or footer. Since there is no
location for metadata, file disks are assumed to have 512 byte sectors and have
a disk length the length of the file.

### VHDMP disk

On Windows, the kernel-mode VHD parser can be used to implement a disk. It supports
all kinds of VHDs and VHDXs.

Notably, `VhdmpDisk` still uses `ScsiDisk` for SCSI parsing rather than VHDMP's
internal SCSI interface. This could change if advanced SCSI functionality, such
as copy offload, is needed.

### RAM disk

A RAM disk implements a disk in a `Vec<u8>`. It is useful for testing.

## Limitations

StorVSP does not yet support asynchronous IO. Every IO is issued synchronously
during channel message processing. This significantly limits performance.

Hyper-V's kernel-mode StorVSP supports kernel-mode *parsers* (similar to
OpenVMM's disks). There currently is no way for OpenVMM's StorVSP to make use of
these parsers. It would be reasonable to have an `EvdDisk` type that calls to
kernel-mode StorVSP for this purpose.

## Additional Work

There are several areas remaining to be improved, including

* Asynchronous IO (see above)
* Single-buffered IO (currently we double-buffer IO from the guest)
* Pause support (requires VmBus support)
* Snapshot capability
* ISO support (this is likely possible using the VHDMP driver on Windows)
