# DiamaneOS product configuration

Install at `vendor/diamaneos` in the Android source workspace. Device products
inherit `product.mk` after their framework and hardware inputs.

What every DiamaneOS product shares:

- `product.mk`: the entry point. It inherits `config/common.mk`, selects the
  parts below and adds the Updater to official builds.
- `config/common.mk`: vendor-side selection that `base_vendor.mk` would
  otherwise provide (recovery runtime, compatibility matrix), and the netd log
  level that keeps hardware addresses out of the log.
- `config/wifi.mk`: Android Wi-Fi services, for devices with Wi-Fi.
- `overlay/`: DiamaneOS-wide runtime resource overlays.
- `fonts/`: Sofia Sans Tally, the metric-adjusted Sofia Sans, as the system font
  and the shell's named families, with the script that builds it.
- `media/`: the boot animation.
- `release/`: aconfig values added to GrapheneOS's release config.
- `removed_packages/`: GrapheneOS packages DiamaneOS does not install.
- `gallery/`: Gallery2 reduced to its crop screen while LineageOS's Glimpse is
  the gallery, and the notices of Glimpse's bundled libraries.

Switches in `product.mk`:

- `DIAMANEOS_GALLERY`: the gallery (`glimpse` or `grapheneos`).
- `DIAMANEOS_SCREENSHOT_EDITOR`: the screenshot editor (`canvas`, LineageOS's
  Canvas, or `grapheneos`).

Rules:

- Device-specific configuration, generated hardware inputs and kernel artifacts
  belong in their own repositories. Generic changes belong here, not in a
  device tree.
- Upstream `OFFICIAL_BUILD` must be unset: it selects upstream delivery
  identity.
- `DIAMANEOS_OFFICIAL_BUILD=true` marks a build made by the DiamaneOS builder
  and adds the Updater, which checks DiamaneOS's update server
  (`releases.diamaneos.de`). Other builds leave it unset.

Original code is Apache-2.0; see LICENSE. The fonts in `fonts/` keep their
SIL Open Font License (`fonts/OFL.txt`); `gallery/notices/` holds the licence
texts of Glimpse's bundled libraries.
