# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 The DiamaneOS Project

# OFFICIAL_BUILD enables upstream GrapheneOS delivery configuration.
# A downstream product must not acquire that identity through its environment.
ifneq ($(strip $(OFFICIAL_BUILD)),)
$(error OFFICIAL_BUILD must be unset for DiamaneOS products)
endif

# Products keep their device maker's brand and product identity in the build
# properties (as GrapheneOS does); DiamaneOS is the name shown to people.

$(call inherit-product, vendor/diamaneos/config/common.mk)

# DiamaneOS-wide overlays (overlay/).
PRODUCT_PACKAGES += \
    DiamaneOSFrameworkOverlay \
    DiamaneOSSettingsOverlay

# Sofia Sans for the Tally shell: /product/etc/fonts_customization.xml and the
# fonts it names, in /product/fonts (fonts/).
PRODUCT_PACKAGES += DiamaneOSFontsCustomization
