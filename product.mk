# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 The DiamaneOS Project

# OFFICIAL_BUILD enables upstream GrapheneOS delivery configuration.
# A downstream product must not acquire that identity through its environment.
ifneq ($(strip $(OFFICIAL_BUILD)),)
$(error OFFICIAL_BUILD must be unset for DiamaneOS products)
endif

# DIAMANEOS_OFFICIAL_BUILD=true marks a build made by the DiamaneOS builder
# ("diamaneos build --official"), as GrapheneOS's OFFICIAL_BUILD marks its own:
# it adds the Updater (packages/apps/Updater, the DiamaneOS fork) and its
# overlay (overlay/DiamaneOSUpdaterOverlay) with the certificate pins for
# releases.diamaneos.de. Other builds leave it unset.
ifneq ($(filter-out true,$(strip $(DIAMANEOS_OFFICIAL_BUILD))),)
$(error DIAMANEOS_OFFICIAL_BUILD must be true or unset)
endif
ifeq ($(strip $(DIAMANEOS_OFFICIAL_BUILD)),true)
PRODUCT_PACKAGES += \
    DiamaneOSUpdaterOverlay \
    Updater
endif

# Products keep their device maker's brand and product identity in the build
# properties (as GrapheneOS does). DiamaneOS is the name shown to people.

$(call inherit-product, vendor/diamaneos/config/common.mk)

# System_ext policy for DiamaneOS features of the platform forks (sepolicy/).
SYSTEM_EXT_PRIVATE_SEPOLICY_DIRS += vendor/diamaneos/sepolicy/system_ext/private

# DiamaneOS-wide overlays (overlay/).
PRODUCT_PACKAGES += \
    DiamaneOSDocumentsUIOverlay \
    DiamaneOSFrameworkOverlay \
    DiamaneOSSettingsOverlay \
    DiamaneOSSetupWizardOverlay \
    DiamaneOSSpeechServicesOverlay \
    DiamaneOSSystemUIOverlay \
    DiamaneOSThemesOverlay \
    DiamaneOSWifiOverlay

# Tally colour overlays for first-party apps (overlay/apps/).
$(call inherit-product, vendor/diamaneos/overlay/apps/apps.mk)

# GrapheneOS packages that DiamaneOS does not install (removed_packages/).
PRODUCT_PACKAGES += DiamaneOSRemovedPackages

# Gallery and screenshot editor: one switch each, with the defaults below. The
# build environment or a product (before inheriting this file) may set another
# value.
#
# DIAMANEOS_GALLERY
#   glimpse     LineageOS's Glimpse (packages/apps/Glimpse, forked without
#               network access) is the gallery and holds the system gallery
#               role. Its own overlay sets config_systemGallery, and gallery/
#               adds its bundled libraries' notices. Gallery2 stays installed
#               for its crop screen only (gallery/): the profile photo picker
#               needs a crop handler, and Glimpse has none.
#   grapheneos  GrapheneOS's own gallery selection.
# Glimpse overrides GrapheneOS's Gallery module, so a tree that has
# GrapheneOS's own gallery (external/Gallery) must use grapheneos.
DIAMANEOS_GALLERY ?= glimpse
ifeq ($(DIAMANEOS_GALLERY),glimpse)
ifneq ($(wildcard external/Gallery/Android.bp),)
$(error GrapheneOS ships its own gallery (external/Gallery): set DIAMANEOS_GALLERY := grapheneos)
endif
PRODUCT_PACKAGES += \
    DiamaneOSGallery2CropOnly \
    DiamaneOSGlimpseLibraryNotices \
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

# The Pleat boot animation (media/Android.bp), in place of GrapheneOS's
# module of the same name.
PRODUCT_PACKAGES += bootanimation_zip

# aconfig values added to GrapheneOS's release config (release/): Files keeps
# its trash flow off and turns its new archive code on.
# Android also finds this map on its own (build/make core/release_config.mk
# reads vendor/*/release/). Naming it here keeps that working if a tree ever
# restricts the search.
PRODUCT_RELEASE_CONFIG_MAPS += vendor/diamaneos/release/release_config_map.textproto
