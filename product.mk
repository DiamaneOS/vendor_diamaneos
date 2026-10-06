# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 The DiamaneOS Project

# OFFICIAL_BUILD enables upstream GrapheneOS delivery configuration.
# A downstream product must not acquire that identity through its environment.
ifneq ($(strip $(OFFICIAL_BUILD)),)
$(error OFFICIAL_BUILD must be unset for DiamaneOS products)
endif

# DIAMANEOS_OFFICIAL_BUILD=true marks a build made by the DiamaneOS builder
# ("diamaneos build --official"), as GrapheneOS's OFFICIAL_BUILD marks its own:
# it adds the Updater (packages/apps/Updater, the DiamaneOS fork), which checks
# releases.diamaneos.de for updates. Other builds leave it unset.
ifneq ($(filter-out true,$(strip $(DIAMANEOS_OFFICIAL_BUILD))),)
$(error DIAMANEOS_OFFICIAL_BUILD must be true or unset)
endif
ifeq ($(strip $(DIAMANEOS_OFFICIAL_BUILD)),true)
PRODUCT_PACKAGES += Updater
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

# Gallery and screenshot editor: one switch each. The defaults below are the
# FP6's; the build environment or a product (before inheriting this file) may
# set another value.
#
# DIAMANEOS_GALLERY
#   glimpse     LineageOS's Glimpse (packages/apps/Glimpse, unmodified) is the
#               gallery and holds the system gallery role; its own overlay sets
#               config_systemGallery. Gallery2 stays installed for its crop
#               screen only (gallery/): the profile photo picker needs a crop
#               handler, and Glimpse has none.
#   grapheneos  GrapheneOS's own gallery selection.
# Glimpse overrides GrapheneOS's future Gallery module, so a tree that has
# GrapheneOS's new gallery (external/Gallery) must use grapheneos.
DIAMANEOS_GALLERY ?= glimpse
ifeq ($(DIAMANEOS_GALLERY),glimpse)
ifneq ($(wildcard external/Gallery/Android.bp),)
$(error GrapheneOS ships its own gallery (external/Gallery): set DIAMANEOS_GALLERY := grapheneos)
endif
PRODUCT_PACKAGES += \
    DiamaneOSGallery2CropOnly \
    Glimpse
else ifneq ($(DIAMANEOS_GALLERY),grapheneos)
$(error DIAMANEOS_GALLERY must be glimpse or grapheneos)
endif

# DIAMANEOS_SCREENSHOT_EDITOR
#   canvas      LineageOS's Canvas (packages/apps/Canvas, unmodified) edits
#               screenshots: SystemUI's preferred editor
#               (overlay/DiamaneOSScreenshotEditorOverlay).
#   grapheneos  SystemUI's default: Edit offers the apps that edit images.
DIAMANEOS_SCREENSHOT_EDITOR ?= canvas
ifeq ($(DIAMANEOS_SCREENSHOT_EDITOR),canvas)
PRODUCT_PACKAGES += \
    Canvas \
    DiamaneOSScreenshotEditorOverlay
else ifneq ($(DIAMANEOS_SCREENSHOT_EDITOR),grapheneos)
$(error DIAMANEOS_SCREENSHOT_EDITOR must be canvas or grapheneos)
endif

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
