# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 The DiamaneOS Project

# For devices with an eUICC. The device inherits this next to its eSIM manager
# (DiamaneOSEuicc).

# The framework's eUICC transport logs every ES10 command and response in full
# at verbose level, on every build (TransmitApduLogicalChannelInvocation
# "Send:"/"Response:", ApduSender "Full APDU response"): profile lists with
# ICCIDs and, during a download, the activation code's matching ID, the IMEI
# and the eUICC certificate with the EID. Keep these tags at info.
PRODUCT_VENDOR_PROPERTIES += \
    log.tag.TransApdu=I \
    log.tag.ApduSender-0=I \
    log.tag.ApduSender-1=I
