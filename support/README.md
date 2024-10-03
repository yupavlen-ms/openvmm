This directory is for library and infrastructure crates that are VM agnostic.

Or, in other words:

- They contain no reference to VMs or VM concepts at all
- They contain no dependencies to crates in the repo other than crates in this
  directory
- They are general purpose enough that they could be open source and used by
  other projects

One way to think of this folder is OpenVMM's private crates.io mirror for crates
that are not yet ready to be open sourced, but could be.

Please name crates based on what they provide, and not general catch all names
like "util, base, common" based on what they contain. See the section in the
OpenVMM guide on naming crates.
