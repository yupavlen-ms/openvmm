# VmBus

VmBus is a proprietary paravirtualized device platform that was designed as part
of Hyper-V. It provides a way for the host to offer _channels_ to the guest that
allow binary messages to be passed back and forth. These channels are used to
provide device communication, and there are VmBus devices for a variety of
purposes:

* [Networking](../net.md)
* [Block storage](../block.md)
* Keyboard
* Mouse
* 2D Video
* GPU
* Sockets
* Pipes

The host implementation of the a VmBus device is often called a VSP
(Virtualization Service Provider), and the guest driver is often called a VSC
(Virtualization Service Client).
