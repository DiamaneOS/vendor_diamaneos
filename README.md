# DiamaneOS product configuration

Install at `vendor/diamaneos` in the Android source workspace. Device products
inherit `product.mk` after their framework and hardware inputs.

What every DiamaneOS product shares:

- `product.mk`: product identity; inherits `config/common.mk`.
- `config/common.mk`: vendor-side selection that `base_vendor.mk` would
  otherwise provide (recovery runtime, compatibility matrix), and the netd log
  level that keeps hardware addresses out of the log.
- `config/wifi.mk`: Android Wi-Fi services, for devices with Wi-Fi.
- `overlay/`: DiamaneOS-wide runtime resource overlays.
- `fonts/`: Sofia Sans for the shell, as named font families.
- `media/`: the boot animation.

Device-specific configuration, generated hardware inputs and kernel artifacts
belong to their respective repositories. Generic changes belong here rather
than in a device tree.
Upstream `OFFICIAL_BUILD` must be unset: it selects upstream delivery identity.
This initial configuration defines no update service or release endpoint.

- Device-specific configuration, generated hardware inputs and kernel artifacts
  belong in their own repositories. Generic changes belong here, not in a
  device tree.
- Upstream `OFFICIAL_BUILD` must be unset: it selects upstream delivery
  identity.
- `DIAMANEOS_OFFICIAL_BUILD=true` marks a build made by the DiamaneOS builder
  and adds the Updater, which checks DiamaneOS's update server
  (`releases.diamaneos.de`). Other builds leave it unset.

Original code is Apache-2.0; see LICENSE. The fonts in `fonts/` keep their SIL
Open Font License (`fonts/OFL.txt`).
