# Inspection

As OpenVMM processes are long-running, it is important to be able to extract
state from them at runtime. There are many ways to do this--via live debugging,
a dump file, explicit logging or tracing, performance counters, or even eprintln
statements. Although these techniques all have their uses, none of them allows
for easy programmatic queries of arbitrary state in production.

To support production use, OpenVMM supports an interface to retrieve
hierarchical state information. This interface is backed by the `inspect`
framework, which is centered around the `Inspect` trait. Objects that want to
expose programmatic state information implement this trait and are attached to
the inspect object tree via an existing parent-child relationship (e.g. via a
PCI bus) or by an explicit registration.

Most components that are part of OpenVMM should participate in the inspect tree.

Ultimately the inspect tree's contents should be stable so that it can be used
in automated tooling for tracking down bugs and performance issues. For now,
this is not a concern.
