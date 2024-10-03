This directory contains files needed to bootstrap the guest with the pipette
agent.

* `meta-data` and `user-data`: cloud-init files for Linux guests
* `imc.hiv`: an IMC hive for Windows guests

To update `imc.hiv`, on a Windows machine run `cargo run -p make_imc_hive PATH/TO/imc.hiv`
