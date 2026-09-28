# DiamaneOS product configuration

Install this repository at `vendor/diamaneos` in the Android source workspace.
Device products inherit `product.mk` after their framework and hardware inputs.

This repository owns what every DiamaneOS product shares:

- `product.mk`: product identity; inherits `config/common.mk`.
- `config/common.mk`: vendor-side selection that `base_vendor.mk` would
  otherwise provide (recovery runtime, compatibility matrix), and adb
  authorization for debuggable builds.
- `config/wifi.mk`: Android Wi-Fi services, for devices with Wi-Fi to inherit.
- `overlay/`: DiamaneOS-wide runtime resource overlays.
- `fonts/`: Sofia Sans for the shell, as named font families.
- `media/`: the boot animation.
- `removed_packages/`: GrapheneOS packages DiamaneOS does not install.

Device-specific configuration, generated hardware inputs and kernel artifacts
belong to their respective repositories. Generic changes belong here rather
than in a device tree.
Upstream `OFFICIAL_BUILD` must be unset: it selects upstream delivery identity.
This initial configuration defines no update service or release endpoint.

Original code is Apache-2.0; see LICENSE. The fonts in `fonts/` keep their
SIL Open Font License (`fonts/OFL.txt`).
