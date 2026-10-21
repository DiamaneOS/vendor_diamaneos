# Camera prebuilt

Presigned Camera built from the DiamaneOS Camera source. The APK and its matching APK signature scheme v4 sidecar retain their signatures when included in the OS.

Source revisions, artifact hashes and the APK certificate digest are recorded in [provenance.json](provenance.json).

From version 9304 the Camera needs its CameraProcessor app: add
`prebuilt/processor-release.apk` and its idsig, a second `android_app_import`
named `CameraProcessor` (product_specific, preprocessed) and
`required: ["CameraProcessor"]` on the Camera module.
