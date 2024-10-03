## Virtio-fs

Virtio-fs is an alternative method of sharing files with a Linux guest that is currently under
development. Virtio-fs uses the Filesystem in Userspace (FUSE) protocol, and potentially allows
for greater performance and higher fidelity than 9p. Virtio-fs will also use [LxUtil](lxutil.md) to
support Windows and Linux hosts.

Like virtio-9p, virtio-fs uses [virtio](../infra/virtio.md) to communicate with the host.

### Usage

Virtio-fs file systems are added to the VM by specifying the `--virtio-fs` command line option when
running OpenVMM. This argument takes a value of the format `tag:root`, where `tag` is the mount tag
used to identify the virtio device in the VM, and `root` is the root path of the file system share
on the host.

For example, the argument `--virtio-fs=myfs:C:\` creates a virtio-fs file system that exposes the
host's entire C: drive using the mount tag `myfs`.

To use the file system in the guest, it must be mounted, which is done by running the following
command as root:

```
mount -t virtiofs tag /mnt/point
```

Where `tag` matches the mount tag provided in the `--virtio-fs` argument, and `/mnt/point` is the
directory where you want to mount the file system.

You can create multiple 9p file systems by specifying the `--virtio-fs` option more than once, with
different mount tags.

### Details

When the `--virtio-fs` option is specified, a `VirtioFsDevice` is created, which creates a virtio
PCI device to the guest. This forwards FUSE messages to a `VirtioFs` instance, which implements the
file system.

Virtio-fs uses FUSE, but there is no official FUSE crate for Rust. An [open source crate](https://github.com/zargony/fuse-rs)
exists, but did not meet our requirements for virtio-fs. Therefore, OpenVMM comes with its own FUSE
crate that implements the FUSE protocol.

The virtio-fs server is still under development and may not support all functionality.

### Debugging

You can set the HVLITE_LOG environment variable to control the logging state. To
enable detailed tracing of virtio-fs, you can set it for the `fuse` and
`virtiofs` targets:

```
set HVLITE_LOG=fuse=trace,virtiofs=trace
```

This will cause it to log every request and reply, so this is very verbose.

Because virtio-fs logging is so verbose, it's also recommended to use `--log-file` to write the
log to a file instead of stderr.

### See also

- [Virtio-fs project page](https://virtio-fs.gitlab.io/)
- [Libfuse documentation](http://libfuse.github.io/doxygen/index.html)
- [FUSE protocol overview](https://www.man7.org/linux/man-pages/man4/fuse.4.html) (out of date)
- Linux kernel FUSE documentation
  - [FUSE](https://www.kernel.org/doc/html/latest/filesystems/fuse.html)
  - [FUSE I/O modes](https://www.kernel.org/doc/Documentation/filesystems/fuse-io.txt)
- [Linux kernel virtio-fs documentation](https://www.kernel.org/doc/html/latest/filesystems/virtiofs.html)
