# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 The DiamaneOS Project
# Recovery package selection: Copyright (C) 2018 The Android Open Source Project

# Configuration shared by every DiamaneOS product. Products build on
# generic_system without base_vendor.mk, so some of its vendor-side selection is
# restated here.

# Debuggable builds still ask on the phone before trusting a computer for adb.
# adbd skips that check on userdebug builds and unlocked phones unless this is
# set, and gen_build_prop sets it only for user builds.
ifneq ($(TARGET_BUILD_VARIANT),user)
PRODUCT_SYSTEM_PROPERTIES += ro.adb.secure=1
endif

# User builds log no hardware identifiers. netd logs every binder call it
# serves, with arguments and results, at info level (tag netd); its interface
# configuration calls carry the interface's hardware address, the factory
# Wi-Fi MAC until Android sets a randomised one. Keep its warnings and errors;
# `dumpsys netd` still lists the calls. Debuggable builds keep the info lines.
ifeq ($(TARGET_BUILD_VARIANT),user)
PRODUCT_PRODUCT_PROPERTIES += log.tag.netd=W
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

