# Networking

Networking in OpenVMM is currently implemented purely in user mode. It is divided
into devices, which are the interfaces by which the guest can communicate on the
network, and endpoints, which are the backends that allow packets to be sent and
received.

## Devices

### NetVSP

This is an implementation of the VmBus network device, which was originally
designed as a transport for [RemoteNDIS (RNDIS)][rndis].

Unlike most VmBus devices, NetVSP uses additional GPADLs to back the *send and
receive buffers*. These buffers are used to store network packets that are in
the process of being sent or received so that they do not have to be copied
through the ring buffer.

[rndis]: https://docs.microsoft.com/en-us/windows-hardware/drivers/network/overview-of-remote-ndis--rndis-

### Virtio
This is the standard virtual device protocol used by Linux. Communication is
via queues setup in guest memory, shared with the host.

## Endpoints

### Consomme

The Consomme endpoint implements a NAT in user mode. This requires no special
privileges or capabilities on the host--it just uses ordinary socket APIs. As
such, it can be slow, and IP addresses are not routable, but it otherwise works
well.

### Direct IO (DIO)

On Windows, there is a kernel-mode network switch implementation with a variety
of capabilities. In Hyper-V, this switch is used to directly implement the
NetVSP protocol, which is fast but somewhat unsafe. OpenVMM cannot yet use this
functionality since this requires kernel-mode VmBus channel support.

In the meantime, OpenVMM supports the user-mode interface to the switch, called
direct IO. This was originally designed for use by the emulated network card
supported by Hyper-V. It accepts packets to be sent via calls to WriteFile, and
it supplies received packets via calls to ReadFile.

To hook OpenVMM up to the switch, one needs a switch, NIC, and port. Currently
OpenVMM will create the NIC and port during worker process start, but this will
likely change in the future to allow the management stack to create the port
object (likely via a call to HNS).
