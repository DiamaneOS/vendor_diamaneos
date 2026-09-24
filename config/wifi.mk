# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 The DiamaneOS Project

# Android Wi-Fi services for devices with Wi-Fi. The device adds its vendor
# Wi-Fi HAL (BOARD_WLAN_DEVICE) and chip-specific driver configuration.
$(call soong_config_set,wpa_supplicant_8,wifi_hidl_unified_supplicant_service_rc_entry,true)
PRODUCT_PACKAGES += \
    android.hardware.wifi-service \
    wpa_supplicant \
    wificond
PRODUCT_COPY_FILES += \
    frameworks/native/data/etc/android.hardware.wifi.xml:$(TARGET_COPY_OUT_VENDOR)/etc/permissions/android.hardware.wifi.xml
