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
# properties (as GrapheneOS does). DiamaneOS is the name shown to people.

$(call inherit-product, vendor/diamaneos/config/common.mk)

# DiamaneOS-wide overlays (overlay/).
PRODUCT_PACKAGES += \
    DiamaneOSSettingsOverlay \
    DiamaneOSSetupWizardOverlay \
    DiamaneOSSpeechServicesOverlay
