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
    DiamaneOSDocumentsUIOverlay \
    DiamaneOSFrameworkOverlay \
    DiamaneOSSettingsOverlay \
    DiamaneOSSetupWizardOverlay \
    DiamaneOSSystemUIOverlay \
    DiamaneOSThemesOverlay

# Tally colour overlays for first-party apps (overlay/apps/).
$(call inherit-product, vendor/diamaneos/overlay/apps/apps.mk)

# GrapheneOS packages that DiamaneOS does not install (removed_packages/).
PRODUCT_PACKAGES += DiamaneOSRemovedPackages

# Sofia Sans Tally, the metric-adjusted Sofia Sans, as the system font
# (sans-serif) and the Tally shell's named families:
# /product/etc/fonts_customization.xml and the fonts it names, in
# /product/fonts (fonts/).
PRODUCT_PACKAGES += DiamaneOSFontsCustomization

# The Pleat boot animation (media/, from the DiamaneOS brand assets; zips of
# stored entries). bootanimation plays
# /product/media/bootanimation.zip, or bootanimation-dark.zip when ro.boot.theme
# is 1, and does not fall back from one to the other, so both are installed.
# They are the same file.
PRODUCT_COPY_FILES += \
    vendor/diamaneos/media/bootanimation.zip:$(TARGET_COPY_OUT_PRODUCT)/media/bootanimation.zip \
    vendor/diamaneos/media/bootanimation-dark.zip:$(TARGET_COPY_OUT_PRODUCT)/media/bootanimation-dark.zip

# aconfig values added to GrapheneOS's release config (release/): Files keeps
# its trash flow off until it passes its security review; the new archive code
# is on after its review and fuzzing.
# Android also finds this map on its own (build/make core/release_config.mk
# reads vendor/*/release/); naming it here keeps that working if a tree ever
# restricts the search.
PRODUCT_RELEASE_CONFIG_MAPS += vendor/diamaneos/release/release_config_map.textproto
