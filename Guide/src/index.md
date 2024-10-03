# Introduction

OpenVMM is a virtual machine monitor (VMM) written in Rust for Windows and Linux.
It was codenamed HvLite so you may see some references to this name in the
documentation and code. The HvLite name comes from the project being a
lightweight redesign of the Hyper-V VMM (virtualization stack), with the goal of
supporting most of the guest-visible features of Hyper-V. However, OpenVMM has a
few significant design departures from Hyper-V:

* Cross-platform: OpenVMM runs on Windows and Linux, and it can run on either the
  Microsoft hypervisor or on KVM.

* Decoupled: Unlike Hyper-V, OpenVMM is built in its own repo and can run on
  multiple versions of Windows. It runs as an individual process, without the
  presence of any control service/daemon. This improves development and
  deployment time and simplifies servicing.

* Public APIs: Wherever possible, OpenVMM depends on public Windows (and Linux)
  APIs. It uses the Windows Hypervisor Platform (WHP) interface to interact with
  the Microsoft hypervisor.

* User mode: OpenVMM implements as much as possible in user mode. This reduces
  the impact of successful guest attacks, improves developer productivity, and
  simplifies servicing.

An important use case of the OpenVMM VMM is [OpenHCL](./openhcl/index.md),
an environment for providing virtualization services from inside Virtual Trust
Level 2 (VTL2) in a guest virtual machine rather than in the privileged
host/root partition.

This guide describes the architecture and provides developer guidelines for
both OpenVMM and OpenHCL. For instructions on installing dependencies,
please refer to the getting started guide for [Windows](./getting_started.md)
or [WSL2](./getting_started_wsl.md). **OpenHCL can only be built on linux,
and WSL2 is the only platform that is currently supported for OpenHCL
development.** Once you have the dependencies installed (and optionally
setup your [development environment](./ide_setup.md)), please
refer to the instructions for building [OpenVMM](./openvmm/build.md) or
[OpenHCL](./openhcl/build.md)

The latest version of this guide can be found at [here](https://aka.ms/openvmmguide). The
source code for OpenVMM can be found at [https://aka.ms/openvmm](https://aka.ms/openvmm).
