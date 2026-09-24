# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 The DiamaneOS Project
# Recovery package selection: Copyright (C) 2018 The Android Open Source Project

# Configuration shared by every DiamaneOS product. Products build on
# generic_system without base_vendor.mk, so some of its vendor-side selection is
# restated here.

# Diagnostic (non-user) builds only: trust a developer adb key kept outside
# version control, so adb works before the setup UI exists. Inert for user builds.
ifneq ($(TARGET_BUILD_VARIANT),user)
  ifneq ($(wildcard vendor/diamaneos-diag/adb_keys),)
    PRODUCT_ADB_KEYS := vendor/diamaneos-diag/adb_keys
  endif
endif

# Generate the standard device compatibility matrix and system SDK requirements.
# generic_system does not inherit the base_vendor package selection.
PRODUCT_PACKAGES += vendor_compatibility_matrix.xml

# Select the platform recovery runtime explicitly: image generation alone does
# not select these packages when generic_system is used without base_vendor.
# This follows base_vendor.mk's recovery group; fastbootd serves dynamic partitions.
PRODUCT_PACKAGES += \
    adbd.recovery \
    cgroups.recovery.json \
    charger.recovery \
    fastbootd \
    init_second_stage.recovery \
    ld.config.recovery.txt \
    linker.recovery \
    otacerts.recovery \
    recovery \
    servicemanager.recovery \
    shell_and_utilities_recovery \
    watchdogd.recovery

PRODUCT_VENDOR_PROPERTIES += \
    ro.recovery.usb.vid=18D1 \
    ro.recovery.usb.adb.pid=D001 \
    ro.recovery.usb.fastboot.pid=4EE0

