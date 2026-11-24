# DiamaneOS: one user per fsvmd service (fsvmd/fsvmd.rc), in the vendor's reserved OEM range, below the device's own
# and its IMS services' (2989 to 2999). init runs each service as its user, so no fsvmd shares a user with another,
# none runs as the system user, and no fsvmd service holds setuid or setgid. The slots match vold's caps
# (system/vold fs/Fsvm.cpp): one probe at a time, kMaxServing (6) served volumes, kMaxObbVms (4) OBB images.
# scripts/p3-slots-check.py checks that they agree.

[AID_VENDOR_FSVMD_PROBE]
value: 2970

[AID_VENDOR_FSVMD_0]
value: 2971

[AID_VENDOR_FSVMD_1]
value: 2972

[AID_VENDOR_FSVMD_2]
value: 2973

[AID_VENDOR_FSVMD_3]
value: 2974

[AID_VENDOR_FSVMD_4]
value: 2975

[AID_VENDOR_FSVMD_5]
value: 2976

[AID_VENDOR_FSVMD_OBB_0]
value: 2977

[AID_VENDOR_FSVMD_OBB_1]
value: 2978

[AID_VENDOR_FSVMD_OBB_2]
value: 2979

[AID_VENDOR_FSVMD_OBB_3]
value: 2980
