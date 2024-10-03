This directory is for library and infrastructure crates that are provide
VM-related functionality, _without_ being tied to any particular "VMM frontend"
(e.g: OpenVMM, OpenHCL, etc...)

Crates in this directly must not take any direct dependencies on any code
outside of `vm/`, _except_ for crates pulled from crates.io, or crates under
`../support/`.
